"""Load the project's BGE models with ONNX Runtime when Windows blocks PyTorch."""
import sys
import os
from functools import cache

import numpy as np


_REVISIONS = {
    "BAAI/bge-base-en-v1.5": "a5beb1e3e68b9ab74eb54cfd186867f64f240e1a",
    "BAAI/bge-reranker-base": "2cfc18c9415c912f9d8155881c133215df768a70",
}


@cache
def _use_onnx():
    if os.environ.get("ARIA_BGE_BACKEND", "").lower() == "onnx":
        return True
    if sys.platform == "win32":
        try:
            import torch
        except OSError as exc:
            if getattr(exc, "winerror", None) == 4551:
                return True
            raise
    return False


def load_embedder(name):
    if name == "BAAI/bge-base-en-v1.5" and _use_onnx():
        return OnnxEmbedder(name)
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(name, trust_remote_code=False)


def load_reranker(name):
    if name == "BAAI/bge-reranker-base" and _use_onnx():
        return OnnxReranker(name)
    from sentence_transformers import CrossEncoder
    return CrossEncoder(name)


class WindowTokenizer:
    """Expose the token operations the rerankers use to split long documents."""

    model_max_length = 512

    def __init__(self, path):
        self.path = path
        self._tokenizers = {}

    def for_length(self, length):
        from tokenizers import Tokenizer
        if length not in self._tokenizers:
            tokenizer = Tokenizer.from_file(self.path)
            tokenizer.no_padding()
            tokenizer.enable_truncation(max_length=length)
            self._tokenizers[length] = tokenizer
        return self._tokenizers[length]

    def encode(self, text, pair=None, *, add_special_tokens=True, truncation=True, max_length=512):
        return self.for_length(max_length).encode(text, pair, add_special_tokens=add_special_tokens).ids

    def __call__(self, text, **options):
        return {"input_ids": self.encode(text, **options)}

    def decode(self, tokens, skip_special_tokens=True):
        return self.for_length(512).decode(tokens, skip_special_tokens=skip_special_tokens)


class OnnxBgeModel:
    max_length = max_seq_length = 512

    def __init__(self, name):
        from huggingface_hub import hf_hub_download, try_to_load_from_cache
        from onnxruntime import InferenceSession
        from tokenizers import Tokenizer

        def model_file(filename):
            revision = _REVISIONS[name]
            cached = try_to_load_from_cache(name, filename, revision=revision)
            if isinstance(cached, str):
                return cached
            return hf_hub_download(name, filename, revision=revision)

        path = model_file("tokenizer.json")
        self.tokenizer = WindowTokenizer(path)
        self.batch_tokenizer = Tokenizer.from_file(path)
        self.batch_tokenizer.enable_truncation(max_length=self.max_length)
        pad = "[PAD]" if name == "BAAI/bge-base-en-v1.5" else "<pad>"
        self.batch_tokenizer.enable_padding(pad_id=self.batch_tokenizer.token_to_id(pad), pad_token=pad)
        self.session = InferenceSession(model_file("onnx/model.onnx"), providers=["CPUExecutionProvider"])

    def run_batch(self, texts):
        tokens = self.batch_tokenizer.encode_batch(texts)
        fields = {"input_ids": "ids", "attention_mask": "attention_mask", "token_type_ids": "type_ids"}
        inputs = {
            item.name: np.asarray([getattr(t, fields[item.name]) for t in tokens], dtype=np.int64)
            for item in self.session.get_inputs()
        }
        return self.session.run([self.session.get_outputs()[0].name], inputs)[0]


class OnnxEmbedder(OnnxBgeModel):
    def get_embedding_dimension(self):
        return 768

    def encode(self, texts, *, batch_size=32, normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False):
        single = isinstance(texts, str)
        items = [texts] if single else texts
        batches = []
        for i in range(0, len(items), batch_size):
            # BGE-base-en-v1.5 pools the first (CLS) token.
            vectors = self.run_batch(items[i:i + batch_size])[:, 0, :]
            if normalize_embeddings:
                vectors = vectors / np.maximum(np.linalg.norm(vectors, axis=1, keepdims=True), 1e-12)
            batches.append(vectors)
        output = np.concatenate(batches) if batches else np.empty((0, 768), dtype=np.float32)
        return output[0] if single else output


class OnnxReranker(OnnxBgeModel):
    def predict(self, pairs):
        scores = []
        for i in range(0, len(pairs), 8):
            logits = self.run_batch([tuple(pair) for pair in pairs[i:i + 8]]).reshape(-1)
            # CrossEncoder applies sigmoid for this single-label model.
            scores.extend(np.exp(-np.logaddexp(0, -logits)))
        return np.asarray(scores, dtype=np.float32)

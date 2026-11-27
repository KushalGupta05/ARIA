# Retrieval and investigation worker

The worker reads a flagged host window from SQLite, builds investigation queries, searches Chroma, deduplicates and reranks candidate documents, then requests a structured case summary. A response validator records warnings, and the worker writes the case into the analyst database. The risk score comes from telemetry and process context. [Worker](aria_rag_consumer.py) · [Prompt template](src/templates/aria_triage_prompt_v2.j2) · [Response validator](src/response_validator.py)

## Build a small local index

Start at the repository root with Python 3.14 and uv installed. The following commands prepare two short, project-authored reference summaries. The first embedding run may download BGE model weights. [uv installation](https://docs.astral.sh/uv/getting-started/installation/)

```sh
cd ML_Model/RAG_Pipeline
uv sync --locked
python -c "from pathlib import Path; from shutil import copyfile; p=Path('data/raw'); p.mkdir(parents=True, exist_ok=True); copyfile('../../examples/techniques.json', p/'parsed_mitre_data.json')"
uv run --locked python index_knowledge.py
```

The sample indexes two chunks in `aria_knowledge_base`. It uses `BAAI/bge-base-en-v1.5` to produce 768-dimensional vectors. Re-running the indexer updates records with the same document IDs. Set the process environment variable `ARIA_BGE_BACKEND=onnx` to use CPU ONNX inference for the BGE embedder and reranker. [Embedding runtime](src/embeddings/bge_runtime.py)

Parsers are available for Enterprise ATT&CK, CAPEC, CISA KEV, NVD, Sigma rules and incident-response playbooks. Each accepts local inputs and writes parsed JSON under `data/raw/` by default. The Sigma parser needs PyYAML, and the PDF parser needs PyPDF2. Obtain the source material from its publisher. [Knowledge parsers](../../RAG_KnowledgeBase) · [Enterprise ATT&CK data](https://github.com/mitre-attack/attack-stix-data)

For example, from the repository root, pass the path of a local Enterprise ATT&CK STIX bundle to the parser and then rerun the indexer.

```sh
python RAG_KnowledgeBase/MITRE_enterprise-attack/parse_attack.py -i "path/to/enterprise-attack.json"
```

## Process live queue entries

1. Start the classifier against your Wazuh lab. The classifier and worker use `var/live/` by default. [Classifier setup](../../docs/classifier.md)
2. In this directory, copy `.env.example` to `.env`. The worker defaults to Ollama on `localhost:11434` and model `qwen3:8b`. Pull that model with `ollama pull qwen3:8b`, or set `OLLAMA_MODEL` to an installed model. [Ollama model page](https://ollama.com/library/qwen3:8b)
3. Run `uv run --locked python aria_rag_consumer.py --once` to process one pending alert. Omit `--once` for the continuous worker.
4. Start the analyst API from the repository root with `python ML_Model/frontend_api.py`. The API serves the built console and reads cases produced by the worker.

Selecting `LLM_PROVIDER=gemini` and supplying a Gemini key and enabled model sends the prompt, host details and retrieved references to that provider. The default Ollama configuration sends generation requests to the local service. [Example provider settings](.env.example)

The pipeline proposes investigative associations. A high thread count or an external socket can have an ordinary operational explanation. If generation fails, the worker can save a rule-based fallback with a warning. The analyst owns the disposition.

A local integration run indexed the two example records, consumed one synthetic queue entry, generated a summary using Ollama with `qwen2.5:latest`, and saved it in the case store. The run exercised the ONNX embedding and reranking path. Retrieval relevance and narrative accuracy still need a labeled evaluation set.

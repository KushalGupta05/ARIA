"""Build or update the local retrieval index from parsed knowledge documents."""
from src.embeddings.embedder import DocumentEmbedder
from src.ingestion.chunker import DocumentChunker
from src.ingestion.cleaner import DocumentCleaner
from src.ingestion.loader import DocumentLoader
from src.vector_store.chroma_store import ChromaStore


def main():
    documents = DocumentLoader().load_documents()
    chunks = DocumentChunker().chunk_documents(DocumentCleaner().clean_documents(documents))
    if not chunks:
        raise SystemExit("Add parsed JSON documents under data/raw before indexing.")
    embedder = DocumentEmbedder()
    store = ChromaStore()
    for start in range(0, len(chunks), 128):
        batch = chunks[start:start + 128]
        store.store_documents(batch, embedder.embed_documents(batch))
    print(f"Indexed {len(chunks)} chunks. The collection contains {store.count()} records.")


if __name__ == "__main__":
    main()

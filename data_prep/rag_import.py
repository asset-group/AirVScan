import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from langchain_text_splitters import TokenTextSplitter
from pymilvus import MilvusClient
from tqdm import tqdm

from rag_utils import batch_embed

BASE_DIR = PROJECT_ROOT


def embed_multithread(chunks, batch_size, num_threads):
    data = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        idx = 0
        futures = []
        while idx < len(chunks):
            futures.append(executor.submit(batch_embed, chunks[idx : idx + batch_size]))
            idx += batch_size

        for i, future in enumerate(
            tqdm(as_completed(futures), total=len(futures), desc="Embedding")
        ):
            for doc, vector in future.result():
                data.append({"id": len(data), "vector": vector, "doc": doc})

    return data


def import_document(client: MilvusClient, col: str, docs: list[str] | str):
    token_splitter = TokenTextSplitter(
        model_name="gpt-4o",  # this matches OpenAI tokenizer
        chunk_size=400,  # keep it under the limit
        chunk_overlap=100,  # optional overlap for context
    )

    if isinstance(docs, str):
        docs = [docs]

    chunks = []
    for doc in docs:
        chunks.extend(token_splitter.split_text(doc.replace("\xa0", "")))

    for chunk in tqdm(chunks, desc="Inserting to database"):
        client.insert(col, [{"doc": chunk}])


if __name__ == "__main__":
    client = MilvusClient(str(BASE_DIR / "milvus_demo.db"))

    # Modbus docs
    with open(
        BASE_DIR / "documents/modbus/modbus_converted_by_gemini_obfuscated.md",
        "r",
        encoding="utf8",
    ) as f:
        modbus_docs = f.read()
    import_document(client, "modbus", modbus_docs)

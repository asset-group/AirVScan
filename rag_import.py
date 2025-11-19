import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from langchain_text_splitters import TokenTextSplitter
from pymilvus import MilvusClient
from tqdm import tqdm

from rag_utils import batch_embed


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

    # data = embed_multithread(chunks, batch_size=30, num_threads=16)

    for chunk in tqdm(chunks, desc="Inserting to database"):
        insert_res = client.insert(col, [{"doc": chunk}])


if __name__ == "__main__":
    client = MilvusClient("milvus_demo.db")

    # 5G docs
    # fiveg_docs = []
    # for root, dirs, files in os.walk("sharetechnotes/"):
    #     for file in files:
    #         if file.endswith(".md"):
    #             md_path = os.path.join(root, file)
    #             doc = open(md_path, "r", encoding="utf8").read()
    #             fiveg_docs.append(doc)

    # import_document(client, "fiveg", fiveg_docs)
    # for i in [
    #     "documents/fiveg/ts_124501v160501p_nas.pdf.md",
    #     "documents/fiveg/ts_138322v160100p_rlc.pdf.md",
    #     "documents/fiveg/ts_138331v160100p_rrc.pdf.md",
    # ]:
    #     with open(i, "r", encoding="utf8") as f:
    #         fiveg_docs = f.read()
    #     import_document(client, "fiveg", fiveg_docs)

    # Bluetooth docs
    # with open("Core_v4.2.pdf.md", "r", encoding="utf8") as f:
    #     bt_docs = f.read()
    # import_document(client, "bt", bt_docs)

    # Modbus docs
    with open(
        "documents/modbus/modbus_converted_by_gemini_obfuscated.md", "r", encoding="utf8"
    ) as f:
        modbus_docs = f.read()
    import_document(client, "modbus", modbus_docs)

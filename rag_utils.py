from constants import OPENAI_URL, azpro_kksj_key
from openai import OpenAI
from pymilvus import MilvusClient

from utils import Protocol

openai_client = OpenAI(base_url=OPENAI_URL, api_key=azpro_kksj_key)


def emb_text(text):
    return (
        openai_client.embeddings.create(input=text, model="text-embedding-3-small")
        .data[0]
        .embedding
    )


def batch_embed(chunks: list[str]):
    response = openai_client.embeddings.create(input=chunks, model="text-embedding-3-small")
    embeddings = [r.embedding for r in response.data]
    return list(zip(chunks, embeddings))


class DocSearch:
    def __init__(self, db_path: str) -> None:
        self.client = MilvusClient(db_path)

    def search(self, protocol: Protocol, kw: str, num_docs: int = 3):
        res = self.client.search(
            collection_name=protocol,  # target collection
            data=[kw],  # query vectors
            limit=num_docs,  # number of returned entities
            anns_field="sparse",
            output_fields=["doc"],  # specifies fields to be returned
            # search_params=search_params,
        )

        res = [i["entity"]["doc"] for i in res[0]]

        return res


if __name__ == "__main__":
    doc_search = DocSearch("milvus_demo.db")
    count = 0
    for i in doc_search.search("fiveg", "LMP_features_req", 999):
        count += 1

    print(count)

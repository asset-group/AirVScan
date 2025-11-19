from pymilvus import DataType, Function, FunctionType, MilvusClient


def create_col(client: MilvusClient, col_name: str, recreate: bool = False):
    if recreate:
        try:
            client.drop_collection(collection_name=col_name)
        except:
            pass

    # FTS schema
    schema = client.create_schema()
    schema.add_field(field_name="id", datatype=DataType.INT64, is_primary=True, auto_id=True)
    schema.add_field(
        field_name="doc", datatype=DataType.VARCHAR, max_length=1000, enable_analyzer=True
    )
    schema.add_field(field_name="sparse", datatype=DataType.SPARSE_FLOAT_VECTOR)

    bm25_function = Function(
        name="doc_bm25_emb",  # Function name
        input_field_names=["doc"],  # Name of the VARCHAR field containing raw text data
        output_field_names=[
            "sparse"
        ],  # Name of the SPARSE_FLOAT_VECTOR field reserved to store generated embeddings
        function_type=FunctionType.BM25,  # Set to `BM25`
    )

    schema.add_function(bm25_function)

    index_params = client.prepare_index_params()

    index_params.add_index(
        field_name="sparse",
        index_type="SPARSE_INVERTED_INDEX",
        metric_type="BM25",
        params={"inverted_index_algo": "DAAT_MAXSCORE", "bm25_k1": 1.2, "bm25_b": 0.75},
    )

    # create collection
    if not client.has_collection(collection_name=col_name):
        client.create_collection(
            collection_name=col_name, schema=schema, index_params=index_params
        )


if __name__ == "__main__":
    client = MilvusClient("milvus_demo.db")
    # create_col(client, "bt", True)
    # create_col(client, "fiveg", True)
    create_col(client, "modbus", True)


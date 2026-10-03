import re
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from traceback import print_exc
from typing import Literal, TypedDict, TypeVar

import tiktoken
from constants import GOOGLE_KEY, LLM_API_KEY, LLM_API_URL
from langchain.schema import AIMessage
from langchain.schema.runnable import Runnable
from langchain_core.language_models import BaseChatModel
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from utils import ae_logger, random_string

LLMModel = Literal[
    "gpt-4o-mini",
    "gpt-4o-2024-08-06",
    "gemini-1.5-flash-latest",
    "gpt-3.5-turbo-0125",
    "o1-all",
    "o1-pro-all",
    "o3-all",
    "gpt-4o-2024-11-20",
    "gpt-4.1",
    "gemini-2.5-pro-exp-03-25",
    "gemini-2.5-pro",
    "grok-4",
    "o3-2025-04-16",
]


class LLMAnswer(TypedDict):
    prompt: str
    answer: str
    model: LLMModel


def get_llm(model: LLMModel, *, max_output_tokens=512, temperature: float = 0.0) -> BaseChatModel:
    """Gets an LLM model instance for the given model name and parameters.

    Parameters:
    - model_name (str): Name of model to load
    - temperature (float): Sampling temperature (default 0.0)
    - max_output_tokens (int): Max tokens per generation (default 512)

    Returns:
    - An instance of the appropriate Chat interface for the given model

    Note:
    OpenAI documentation: https://platform.openai.com/docs/api-reference/chat/create.
    Take note for `temperature` and `top_p` parameters.
    """
    if model == "o3-2025-04-16":
        return ChatOpenAI(
            timeout=60 * 10,
            model=model,
            temperature=temperature,
            max_tokens=max_output_tokens,  # type: ignore
            base_url=LLM_API_URL or None,
            api_key=LLM_API_KEY,
        )
    if model.startswith("gemini-2.5-pro"):
        return ChatOpenAI(
            timeout=60 * 10,
            model=model,
            temperature=temperature,
            max_tokens=max_output_tokens,  # type: ignore
            base_url=LLM_API_URL or None,
            api_key=LLM_API_KEY,
            top_p=0.1,
        )
    if model == "grok-4":
        return ChatOpenAI(
            timeout=60 * 10,
            model=model,
            temperature=temperature,
            max_tokens=max_output_tokens,  # type: ignore
            base_url=LLM_API_URL or None,
            api_key=LLM_API_KEY,
            top_p=0.1,
        )

    if model in [
        "gpt-4o-2024-08-06",
        "gpt-4o-2024-11-20",
        "gpt-4.1",
        "gpt-4o-mini",
        "gpt-3.5-turbo-0125",
        "o1-all",
        "o1-pro-all",
        "o3-all",
        "o3",
        "o1",
    ]:
        return ChatOpenAI(
            timeout=60 * 3,
            model=model,
            temperature=temperature,
            max_tokens=max_output_tokens,  # type: ignore
            base_url=LLM_API_URL or None,
            api_key=LLM_API_KEY,
            top_p=0.1,
        )
    elif model == "deepseek-r1" or model == "o3-pro" or model == "chatgpt-4o-latest":
        return ChatOpenAI(
            timeout=60 * 7,
            model=model,
            temperature=temperature,
            max_tokens=max_output_tokens,  # type: ignore
            base_url=LLM_API_URL or None,
            api_key=LLM_API_KEY,
            top_p=0.1,
        )
    elif "gemini" in model:
        return ChatGoogleGenerativeAI(
            model=model,
            temperature=temperature,
            max_tokens=max_output_tokens,
            api_key=GOOGLE_KEY,
        )

    raise Exception(f"Model {model} not supported")


@lru_cache(maxsize=256)
def count_token(s: str):
    encoder = tiktoken.encoding_for_model("gpt-4o-2024-11-20")
    return len(encoder.encode(s))


def is_query_beyond_limit(query: str, model: LLMModel):
    # TODO: Gemini
    # check if query is more than the maximum context window of the LLM
    if "gemini" in model:
        # 1 million for gemini-flash, which is quite enough in most scenarios
        return False

    model_max_context: dict[LLMModel, int] = {
        "gpt-4o-2024-11-20": 128 * 1000,
        "gpt-4o-2024-08-06": 128 * 1000,
        "gpt-4.1": 128 * 1000,
        "o1-all": 128 * 1000,
        "o3-all": 128 * 1000,
        "o1-pro-all": 128 * 1000,
        "gpt-4o-mini": 128 * 1000,
        "gpt-3.5-turbo-0125": 16 * 1000,
    }

    encoding_map: dict[LLMModel, tiktoken.Encoding] = {
        "gpt-4o-2024-11-20": tiktoken.encoding_for_model("gpt-4o-2024-11-20"),
        "gpt-4o-2024-08-06": tiktoken.encoding_for_model("gpt-4o-2024-08-06"),
        "gpt-4o-mini": tiktoken.encoding_for_model("gpt-4o-mini"),
        "gpt-4.1": tiktoken.encoding_for_model("gpt-4"),
        "gpt-3.5-turbo-0125": tiktoken.encoding_for_model("gpt-3.5-turbo-0125"),
        "o1-all": tiktoken.encoding_for_model("o1-all"),
        "o3-all": tiktoken.encoding_for_model("o3-all"),
        "o1-pro-all": tiktoken.encoding_for_model("o1-pro-all"),
    }

    encoding = encoding_map[model]

    num_token = len(encoding.encode(query))
    is_beyond = model_max_context[model] - num_token < 1000

    if is_beyond:
        ae_logger.error(
            f"Prompt is too long: {num_token} tokens, while model limit is"
            f" {model_max_context[model]} tokens."
        )

    return is_beyond


def simple_query(
    prompt: str,
    model: LLMModel,
    max_output_token: int = 2048,
    temperature: float = 0.0,
    timeout: int = 200,
) -> str:
    if is_query_beyond_limit(prompt, model):
        return ""

    print("Running simple query:", model, flush=True)
    llm = get_llm(model, max_output_tokens=max_output_token, temperature=temperature)

    res = ""
    num_retry = 0
    max_retry = 5
    while num_retry < max_retry:
        try:
            res = llm.invoke(prompt, timeout=timeout).content
            break
        except Exception as e:
            num_retry += 1
            ae_logger.debug(f"Retry {num_retry}/{max_retry}... reason: {e}")

    if res == "":
        raise Exception("Maximum retry reached.")

    if not isinstance(res, str):
        raise

    return res


def simple_query_parallel(
    prompts: list[str],
    model,
    num_threads: int = 4,
    max_output_token: int = 2048,
    temperature: float = 0.0,
    timeout: int = 200,
) -> list[str]:
    results = []

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(simple_query, prompt, model, max_output_token, temperature, timeout)
            for prompt in prompts
        ]

        for f in futures:
            results.append(f.result())

    return results


LLMStructuredSchema = TypeVar("LLMStructuredSchema", bound=BaseModel)


class PreProcessor(Runnable):
    def __init__(self, func):
        self.func = func

    def invoke(self, input, config=None):
        return self.func(input)


def remove_thinking(text: str) -> str:
    if isinstance(text, AIMessage):
        msg = text.content

    # remove <think>...</think> blocks (non-greedy, multiline)
    return re.sub(r"<think>.*?</think>", "", msg, flags=re.S).strip()


def structured_query(
    query,
    model: LLMModel,
    data_schema: type[LLMStructuredSchema],
    max_output_token: int = 4096,
    temperature: float = 0.0,
) -> LLMStructuredSchema:
    # For more details about LLM structured output, check https://python.langchain.com/docs/how_to/structured_output/
    ae_logger.info(f"Running LLM structured query with model {model}...")

    max_retries = 2
    error = None
    while max_retries > 0:
        max_retries -= 1
        try:
            llm = get_llm(model, max_output_tokens=max_output_token, temperature=temperature)

            # Set up a parser + inject instructions into the prompt template.
            parser = JsonOutputParser(pydantic_object=data_schema)
            prompt = PromptTemplate(
                template=random_string(8)  # trick to disable prompt caching
                + "\n"
                + "Answer the user query.\n{format_instructions}\n{query}\n",
                input_variables=["query"],
                partial_variables={"format_instructions": parser.get_format_instructions()},
            )

            chain = prompt | llm | PreProcessor(remove_thinking) | parser

            res = chain.invoke({"query": query})

            return res
        except Exception as e:
            print_exc()
            error = e
            ae_logger.error(e)

    raise error


# generate test case
class LLMTestCasePkt(BaseModel):
    method: Literal["mutate", "send", "drop"]
    pkt_loc: int
    send_after: int | None


class LLMTestCase(BaseModel):
    testcases: list[list[LLMTestCasePkt]]


class MutatedField(BaseModel):
    field: str = Field(
        description="Name of a mutated field. Please use the exact name specified "
        "in the provided packet sequence. No need to add or remove words, "
        "even they are in a nested structure. "
        'For example, `{"some_field": 2, "some_header":{"a.b.c": <mutated here>}}`, '
        "just use `a.b.c` instead of `some_header.a.b.c`.",
        min_length=1,
    )
    value: int | str | None = Field(description="The mutated filed value, aka malicious value.")
    comments: str = Field(
        description="Comments, analysis and explanations about the mutated field."
    )


class AbnormalPkt(BaseModel):
    type: Literal["mutated", "missing", "duplicated", "reordered"] = Field(
        description="Packet anomaly type"
    )
    pkt_loc: int = Field(description="Abnormal packet `pkt_loc`")
    reordered_pkt_locs: list[tuple[int, int]] = Field(
        description="This field is only applicable when type is **reordered**. "
        "This field stores the locations of reordered packets, each tuple represents "
        "the reordered packets location. There be one or more pairs of reordered packets,"
        "so this field is a **list of tuples**, where each tuple consists of two integers representing"
        "the location of reordered pair."
    )
    fields: list[MutatedField] = Field(
        description="(Only applicable to type `mutate`) The details of mutated fields. "
        "There can be multiple mutated fields in one packet. In packet sequence, there can be "
        "some Wireshark fields which provide some extra information/explanation about the packets "
        "from Wireshark. These fields are `_ws.expert`, `_ws.expert.message`, "
        "`_ws.expert.severity`, `_ws.expert.group`. Please note that these fields are not "
        "packet fields and please do not consider them as abnormal fields."
    )
    comments: str = Field(
        description="Comments, analysis and explanations about the abnormal packet."
    )


class Stage1Res(BaseModel):
    abnormal_packets: list[AbnormalPkt] = Field(
        description="List of abnormal packets found in the packet sequence. "
        "This can be an empty list when you think there is nothing abnormal"
    )
    crash_reason: str = Field(
        description="The possible reasons that lead to the crash. Explanations, "
        "investigations and evidences are welcome to be present here. "
        "This field can be an empty string when you think there is nothing abnormal"
    )
    reproduce_action: str = Field(
        description="Possible actions to reproduce the crash."
        "This field can be an empty string when you think there is nothing abnormal"
    )


if __name__ == "__main__":
    pass

import ast
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from llm_utils import simple_query_parallel

BASE_DIR = PROJECT_ROOT

prompt_tp = """
You are now an expert in 5G field. Use your expert knowledge, explain the following terminologies which are taken from Wireshark. The provided document is in <term>:<glossary> pairs. You need to explain the <term>, in the meantime you can also take <glossary> as a hint. Note that sometimes the glossary may not provide useful hints or may be wrong. The explanation may not be very long, 1 or 2 sentence is enough. It needs to be precise and accurate.

Please start the answer right away without any greetings. You may output in the same format as the original document, aka JSON format.

<document>
{document}
<document>
"""


def main():
    glossary_path = BASE_DIR / "glossary" / "fiveg_fields_glossary.json"
    with open(glossary_path, "r", encoding="utf8") as f:
        glossary = json.load(f)

    temp = {}
    processed = 0
    prompts = []
    for k, v in glossary.items():
        temp[k] = v
        processed += 1

        if len(temp) == 500 or processed == len(glossary):
            prompt = prompt_tp.format(document=temp)
            prompts.append(prompt)
            temp = {}

    res = simple_query_parallel(prompts, "gemini-2.5-pro", 10, 65535, 0, 600)

    res_d = {}
    for i in res:
        print(i, "\n\n")
        try:
            d = ast.literal_eval(i)
            res_d.update(d)
        except Exception as e:
            print("Something wrong here:", e)


if __name__ == "__main__":
    main()

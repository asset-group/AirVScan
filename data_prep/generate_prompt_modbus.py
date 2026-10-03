import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from prompts.my_prompts import get_guidance_prompt
from utils_types import Pkt, PromptType

BASE_DIR = PROJECT_ROOT

with open(os.path.join(BASE_DIR, "obfuscate_dict.json"), "rb") as f:
    obfuscate_dict: dict[str, str] = json.load(f)
    # need to order by original key length
    obfuscate_dict = {
        k: v
        for k, v in sorted(obfuscate_dict.items(), key=lambda item: len(item[0]), reverse=True)
    }


def replace_obfuscated_words(s: str):
    for old, new in obfuscate_dict.items():
        s = re.sub(re.escape(old), new, s, flags=re.IGNORECASE)

    # replace protocol names
    s = re.sub(r"modbus", "Giraffe", s, flags=re.IGNORECASE)

    return s


def gen(prompt_type: PromptType, base_folder: str = ""):
    target_folder = base_folder or os.path.join(BASE_DIR, "captures", "mock-modbus")
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            if not file.endswith("packets.json"):
                continue

            # Load packets from JSON file
            json_path = os.path.join(root, file)
            with open(json_path, "rb") as f:
                pkts_raw = json.load(f)

            pkts = []
            for p in pkts_raw:
                pkts.append(
                    Pkt(
                        loc=p["pkt_loc"],
                        iteration=1,
                        state="",
                        filter=p["pkt_info"],
                        info=p["pkt_info"],
                        fields=p["pkt_fields"],
                    )
                )

            # _, protocol, noise_type = file.split(".")[0].split("_")
            protocol = "modbus"
            noise_type = "normal"

            prompt_folder = os.path.join(root, "prompts", prompt_type, noise_type)
            os.makedirs(prompt_folder, exist_ok=True)
            print(f"Generating {prompt_folder}...")

            for mode in ["full", "full+context", "diff", "diff+context"]:
                prompt_save_path = os.path.join(prompt_folder, f"{mode}.txt")
                prompt = get_guidance_prompt(pkts, 3, protocol, mode, prompt_type)

                prompt = replace_obfuscated_words(prompt)

                # remove Request / Response word
                remove_word = True
                if remove_word:
                    prompt = prompt.replace(" Request", "").replace(" Response", "")

                with open(prompt_save_path, "w", encoding="utf8") as f:
                    f.write(prompt)


if __name__ == "__main__":
    gen("root_cause")
    gen("check_attack")

"""
prompts/
    root_cause/
        noise/
        normal/
    check_attack/
        noise/
        normal/
"""

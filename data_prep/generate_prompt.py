import os
import pickle
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from prompts.my_prompts import get_guidance_prompt
from utils_types import PromptType

BASE_DIR = PROJECT_ROOT


def gen(prompt_type: PromptType, base_folder: str = ""):
    target_folder = base_folder or os.path.join(BASE_DIR, "captures")
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            if not file.endswith(".pickle"):
                continue

            # Load packets from pickle file
            pickle_path = os.path.join(root, file)
            with open(pickle_path, "rb") as f:
                pkts = pickle.load(f)

            try:
                parts = file.split(".")[0].split("_")
                protocol = parts[1]
                noise_type = parts[2]
            except Exception:
                continue

            prompt_folder = os.path.join(root, "prompts", prompt_type, noise_type)
            os.makedirs(prompt_folder, exist_ok=True)
            print(f"Generating {prompt_folder}...")

            for mode in ["full", "full+context", "diff", "diff+context"]:
                prompt_save_path = os.path.join(prompt_folder, f"{mode}.txt")
                prompt = get_guidance_prompt(pkts, 3, protocol, mode, prompt_type)

                with open(prompt_save_path, "w", encoding="utf8") as f:
                    f.write(prompt)


if __name__ == "__main__":
    gen("check_attack")
    gen("root_cause")

"""
prompts/
    root_cause/
        noise/
        normal/
    check_attack/
        noise/
        normal/
"""

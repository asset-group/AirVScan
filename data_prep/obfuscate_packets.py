import json
import os
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from names_generator import generate_name

from utils import extract_keys

BASE_DIR = PROJECT_ROOT


def generate_obfuscated_keywords(search_dir=None):
    random.seed(123)
    obfuscated_kw = {}
    obfuscated_names = set()

    def get_obfuscated_key():
        while True:
            name = generate_name()
            if name not in obfuscated_names:
                obfuscated_names.add(name)
                break
        return name

    target_dir = search_dir or (BASE_DIR / "captures" / "mock-modbus")
    for root, _dirs, files in os.walk(target_dir):
        for file in files:
            if not file.endswith("packets.json"):
                continue

            with open(os.path.join(root, file), "rb") as f:
                packets = json.load(f)

            kw = set()
            for pkt in packets:
                kw.add(pkt["pkt_info"].replace(" Request", "").replace(" Response", ""))
                kw.update(extract_keys(pkt["pkt_fields"]))

            for k in kw:
                if k not in obfuscated_kw:
                    obfuscated_kw[k] = get_obfuscated_key()

    return obfuscated_kw


if __name__ == "__main__":
    kw_map = generate_obfuscated_keywords()
    print(kw_map)

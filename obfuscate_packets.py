import copy
import json
import os
import random

from names_generator import generate_name

from utils import extract_keys

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


for root, dirs, files in os.walk("captures_new/mock-modbus"):
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

print(obfuscated_kw)

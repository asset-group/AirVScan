import json

from generate_prompt_modbus import replace_obfuscated_words

with open("obfuscate_dict.json", "rb") as f:
    obfuscate_dict = json.load(f)


original_document = open(
    "documents/modbus/modbus_converted_by_gemini.md",
    "r",
    encoding="utf8",
).read()

replaced_document = replace_obfuscated_words(original_document)

with open(
    "documents/modbus/modbus_converted_by_gemini_obfuscated.md",
    "w",
    encoding="utf8",
) as f:
    f.write(replaced_document)

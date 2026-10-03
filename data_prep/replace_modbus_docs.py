import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Also allow importing from data_prep directory
DATA_PREP_DIR = Path(__file__).resolve().parent
if str(DATA_PREP_DIR) not in sys.path:
    sys.path.insert(0, str(DATA_PREP_DIR))

from generate_prompt_modbus import replace_obfuscated_words

BASE_DIR = PROJECT_ROOT


def main():
    original_path = BASE_DIR / "documents" / "modbus" / "modbus_converted_by_gemini.md"
    target_path = BASE_DIR / "documents" / "modbus" / "modbus_converted_by_gemini_obfuscated.md"

    with open(original_path, "r", encoding="utf8") as f:
        original_document = f.read()

    replaced_document = replace_obfuscated_words(original_document)

    with open(target_path, "w", encoding="utf8") as f:
        f.write(replaced_document)


if __name__ == "__main__":
    main()

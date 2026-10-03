import os
import sys
from pathlib import Path

import nest_asyncio

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from prompts.my_prompts import get_guidance_prompt
from utils import _get_wd_tool, packet_dissection_reader
from utils_types import Pkt, PromptType

nest_asyncio.apply()

BASE_DIR = PROJECT_ROOT
wd_tool = _get_wd_tool("fiveg", 0)


def convert_packets(capture_path: str):
    pkts = []
    for info, dissection, eh_pkt in packet_dissection_reader(
        capture_path, include_info=True, include_detailed_dissection=True, include_raw=True
    ):
        pkt_dir = "TX" if eh_pkt.packet_data[15] == 1 else "RX"

        pkt_data = (
            b"\x00" * 12
            + b"\x08\x00\x45\x00"
            + b"\x00\x46\x2d\x73\x40\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00"
            + b"\x00\x00"  # fake header
            + eh_pkt.packet_data
        )

        wd_filter = wd_tool.label_pkt(pkt_data)

        pkt = Pkt(
            loc=int(info["No."]),
            iteration=1,
            state=wd_tool.pkt_state(pkt_data, 0),
            filter=f"{pkt_dir}|{wd_filter}",
            info=info["Info"],
            fields=dissection,
        )
        pkts.append(pkt)

    return pkts


# prompts: only check_attack, no noise
# with context and without context
# with diff and full
def gen(prompt_type: PromptType):
    target_dir = BASE_DIR / "captures" / "oneplus-fiveg" / "5guest" / "rrc"
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if not file.endswith(".pcapng"):
                continue

            pkts = convert_packets(os.path.join(root, file))

            protocol = "fiveg"
            noise_type = "normal"

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
    # convert_packets(
    #     "/home/wireless-deep-fuzzer/modules/llmbugcatcher/captures/oneplus-fiveg/5guest/nas/t1/gnb_testcase_1.pcapng"
    # )

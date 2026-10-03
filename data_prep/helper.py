import json
import sys
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pcapng import FileScanner, FileWriter
from pcapng.blocks import InterfaceDescription, SectionHeader

from utils import Protocol, WDissectorTool, packet_dissection_reader


def gen_fields_label(input_path: str, output_path):
    """
    Extract field description together with the field name to form a glossary
    from Wireshark codebase.

    Output a JSON file containing field name and description key pairs.

    Check the example below, field name is `x509ce.policyIdentifier` and item 0: `policyIdentifier`
    and item 6: `CertPolicyId` are possible field description candidates. It is observed that
    Item 0 will always be a non-NULL value while item 6 may be NULL. However, usually item 6
    contains better description. Thus, if item 6 is more preferred over item 0 when choosing the
    description.
    .. code-block:: cpp
        {
            & hf_x509ce_policyIdentifier,
            {
                "policyIdentifier",
                "x509ce.policyIdentifier",
                FT_OID,
                BASE_NONE,
                NULL,
                0,
                "CertPolicyId",
                HFILL
            }
        }

    TODO: Logic below are naive and assuming the C++ code following the exact style as above
    """
    with open(input_path, "r") as f:
        raw = f.read()

    raw = raw + "\n& hf"
    res = {}
    temp = []
    for line in raw.splitlines():
        if "& hf" in line:
            if temp:
                exp1 = temp[1].replace(",", "").strip()
                field = temp[2].replace(",", "").strip()
                exp2 = temp[7].replace(",", "").strip()

                if "NULL" not in exp2:
                    res[field[1:-1]] = exp2[1:-1]
                else:
                    res[field[1:-1]] = exp1[1:-1]
                temp = []
        else:
            temp.append(line)

    with open(output_path, "w", encoding="utf8") as f:
        json.dump(res, f)


@lru_cache
def _get_wd_tool(protocol):
    return WDissectorTool(protocol, 0 if protocol == "fiveg" else 4)


def remove_original_packets(original_capture: str, protocol: Protocol, output_path: str = ""):
    """Remove the recorded **original packets** from WDissector captures so that there is no reference
    packets in the capture.

    Parameters
    ----------
    original_capture : str
        Path to the original capture
    protocol : Protocol
        Protocol that the capture is used
    output_path : str, optional
        Path to the output capture, by default appending `_no_original` to the `original_capture`
    """

    if output_path == "":
        output_path = (
            original_capture.split(".")[0] + "_no_original." + original_capture.split(".")[1]
        )

    wd_tool = _get_wd_tool(protocol)

    shb = None
    idbs = []
    with open(original_capture, "rb") as fp:
        scanner = FileScanner(fp)
        for idx, block in enumerate(scanner):
            if isinstance(block, InterfaceDescription):
                idbs.append(block)
                print(2, block)
            elif shb is None and isinstance(block, SectionHeader):
                shb = block
                print(1, shb)

            if idx >= 16:
                # Section header and interface description are usually at the start  No need to traverse all packets
                break

    assert isinstance(shb, SectionHeader), "A SectionHeader is needed"

    for idb in idbs:
        idb.section = shb
        shb.register_interface(idb)

    output_fp = open(output_path, "wb")
    writer = FileWriter(output_fp, shb)
    print(shb.interfaces)
    pkts = []
    prev_pkt = None
    for pkt_summary, pkt in packet_dissection_reader(original_capture, True, False, True):
        comment = pkt.options.get("opt_comment")

        if comment == "Fuzzed from previous":
            pkts.pop()

        filter = ""
        if prev_pkt is not None:
            filter = wd_tool.label_pkt(prev_pkt.packet_data)

        if comment is None:
            pkt.options.add("opt_comment", "")
        pkt.options["opt_comment"] += f"<{pkt_summary['No.']}|{filter}>"
        pkts.append(pkt)
        prev_pkt = pkt

        if int(pkt_summary["No."]) % 10000 == 0:
            print(f"Loaded {pkt_summary['No.']} packets", flush=True)

    print("Writing packets...")
    for pkt in pkts:
        pkt.section = shb
        writer.write_block(pkt)

    output_fp.close()


def read_log_0709(log_path: str):
    modes = ["full", "diff", "diff+changed field", "diff+changed field&desc"]
    modes_idx = 0

    with open(log_path, "r", encoding="utf8", errors="ignore") as f:
        for line in f:
            line = line[:-1]
            if line.startswith("['"):
                print()
                print(line)
            if line.startswith("Same crash found"):
                print(line)
            if line.startswith("Total"):
                print(modes[modes_idx % 4], line)
                modes_idx += 1


if __name__ == "__main__":
    remove_original_packets(
        str(PROJECT_ROOT / "captures/oneplus-fiveg/mut/1-field/t3/capture_nr5g_gnb_noise.pcapng"),
        "fiveg",
    )
    remove_original_packets(
        str(PROJECT_ROOT / "captures/esp32-bt/mut/1-field/t6/capture_bluetooth_noise.pcapng"),
        "bt",
    )
    remove_original_packets(
        str(PROJECT_ROOT / "captures/esp32-bt/mut/1-field/t5/capture_bluetooth.pcapng"),
        "bt",
    )

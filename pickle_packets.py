import os
import pickle

import nest_asyncio

from utils import WDissectorTool, _get_wd_tool, packet_dissection_reader
from utils_types import Pkt, ProtocolType

nest_asyncio.apply()


def read_pkts(capture_path: str, decoding_offset: int, protocol: ProtocolType):
    wd_tool = _get_wd_tool(protocol, decoding_offset)

    iteration = 1
    pkts = []
    for info, fields, eh_pkt in packet_dissection_reader(
        capture_path,
        include_info=True,
        include_detailed_dissection=True,
        include_raw=True,
    ):
        if "packetlogger" in fields:
            # Packets added by WDissector for recording logs
            if "Iteration" in fields["packetlogger"]["packetlogger.info"]:
                iteration += 1
            continue

        try:
            if protocol == "bt":
                pkt_dir = info["Info"][:2]
            elif protocol == "fiveg":
                pkt_dir = "TX" if eh_pkt.packet_data[49] == 1 else "RX"
            else:
                print(f"Unable to get packet direction for protocol: {protocol}")
        except:
            pkt_dir = "TX"

        wd_filter = wd_tool.label_pkt(eh_pkt.packet_data)

        pkt = Pkt(
            # pkt_bytes=eh_pkt.packet_data,
            loc=int(info["No."]),
            iteration=iteration,
            state=wd_tool.pkt_state(eh_pkt.packet_data, 0),
            filter=f"{pkt_dir}|{wd_filter}",
            info=info["Info"],
            fields=fields,
            # comment="",
        )
        pkts.append(pkt)

    return pkts


if __name__ == "__main__":
    for root, dirs, files in os.walk("captures_new/cypress-bt/benign"):
        for file in files:
            if not file.endswith(".pcapng"):
                continue

            capture_path = os.path.join(root, file)
            noise_type = "noise" if "noise" in file else "normal"
            protocol = "bt" if "-bt" in capture_path else "fiveg"
            decoding_offset = 4 if protocol == "bt" else 0
            pickle_path = os.path.join(root, f"packets_{protocol}_{noise_type}.pickle")

            pkts = read_pkts(capture_path, decoding_offset, protocol)
            with open(pickle_path, "wb") as f:
                pickle.dump(pkts, f)

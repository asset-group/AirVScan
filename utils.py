import datetime
import hashlib
import logging
import os
import random
import re
import signal
import string
import subprocess
import sys
import xml.etree.ElementTree as ET
from functools import cache, lru_cache
from io import BytesIO
from typing import Any, Generator, Literal, TypedDict, overload
from xml.etree.ElementTree import Element

import pyshark
import pyshark.packet
from constants import (
    BT_WD_MODEL_CONFIG,
    BT_WD_SM_CONFIG,
    FIVEG_WD_MODEL_CONFIG,
    FIVEG_WD_SM_CONFIG,
    RUN_LOG_PATH,
    TSHARK_PATH,
    WIFI_WD_MODEL_CONFIG,
    WIFI_WD_SM_CONFIG,
)
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket
from pcapng.exceptions import TruncatedFile
from pyshark.packet.packet import Packet as PysharkPacket
from pyshark.packet.packet_summary import PacketSummary as PysharkPacketSummary
from wdissector import (
    WD_DIR_RX,
    WD_DIR_TX,
    WD_MODE_FULL,
    Machine,
    WDPacketLabelGenerator,
    packet_read_field_bitmask,
    packet_read_field_bitmask_offset,
    packet_read_field_offset,
    packet_read_field_size,
    packet_summary,
    wd_field,
    wd_packet_dissect,
    wd_packet_show,
    wd_packet_show_pdml,
    wd_packet_summary,
    wd_pkt_label,
    wd_read_field,
    wd_register_field,
    wd_set_dissection_mode,
    wd_set_packet_direction,
)

from utils_types import Crash, FuzzedPkt, Pkt, ProtocolType


@lru_cache(maxsize=None)
def _cached_wd_tool(protocol: ProtocolType, offset: int):
    return WDissectorTool(protocol, offset)


def _get_wd_tool(protocol: ProtocolType, offset: int):
    return _cached_wd_tool(protocol, offset)


def assign_crash_ids_wdissector(crashes: list[Crash]):
    """
    Default crash identifier assignment function for WDissector, which assigns only
    crash states as crash identifier.

    Parameters
    ----------
    crashes : list[Crash]
        List of crashes from a capture file

    Returns
    -------
    None
    """
    # TODO: add logic for [Timeout]
    for crash in crashes:
        if crash.type == "normal":
            find_res = re.findall(
                rb"\[Crash\] (Crash detected at state|Device Removed at state) (.*)",
                crash.raw,
            )
            if len(find_res) > 0:
                identifier = find_res[0][1].decode()
                identifier = identifier.replace('"', "")
                crash.identifier = identifier
            else:
                # TODO: fallback to last fuzzed packet state
                crash.identifier = "timeout_" + crash.fuzzed_pkts[-1].state
        elif crash.type == "timeout":
            try:
                crash.identifier = "timeout_" + crash.fuzzed_pkts[-1].state
            except:
                # Temporary solution for some 5G captures: there is nothing of fuzzed packets
                # associated with some of crashes
                crash.identifier = "timeout_"
        else:
            ae_logger.error(f"Invalid crash type: {crash.type}")


###########


def count_mut_dup(exploit_path: str) -> tuple[int, int]:
    """
    Count the number of mutated and duplicated packets inside a exploit script.

    Parameters
    ----------
    exploit_path : str
        Path to the exploit script

    Returns
    -------
    mut_count : int
        Number of mutated packets in the exploit
    dup_count : int
        Number of duplicated packets in the exploit
    """
    # count the number of mutated and duplicated packets inside exploit_path
    exploit_content = open(exploit_path, "r", encoding="utf8", errors="ignore").read()
    mut_count = exploit_content.count("Send mutated packet now")
    dup_count = exploit_content.count("Send duplicated packet now")

    return mut_count, dup_count


# session_id = random_string(4)
# ae_logger = get_logger(f"ae_{human_current_date()}_{session_id}")


def clean_up_process(proc_name_keyword: str, sig=signal.SIGKILL):
    """
    Helper function to kill processes whose name contains given keyword.

    As the exploit is executed with `script` command and the exploit script itself will spawn other
    processes, there might be some orphan processes left. These processes might still take up
    resources like CPU or modem, so need to clean up. Be careful to use a specific keyword so that
    no innocent processes will be killed. The command to run the exploits are like:
    - `script /tmp/tmp1edlcn4x --flush` or
    - `sudo bin/lte_fuzzer --exploit=mac_sch_auto_fuzz_exploit_8263 --EnableSimulator=false`.

    Parameter
    ---------
    proc_name_keyword : str
        Process name keyword

    Returns
    -------
    None
    """
    try:
        pids = (
            subprocess.check_output(["pgrep", "-f", proc_name_keyword])
            .decode()
            .strip()
            .split("\n")
        )
        pids = [int(pid) for pid in pids]
        for pid in pids:
            try:
                os.kill(pid, sig)
            except:
                pass
    except:
        pass


def find_mutation_loc(
    protocol: str, original_pkt_bytes: bytes, mutated_pkt_bytes: bytes
) -> list[tuple[int, str]]:
    """
    Find the mutation locations by comparing the two packets.

    Parameters
    ----------
    protocol : str
        Protocol which the packet bytes belong to
    original_pkt_bytes : bytes
        Original packet data
    mutated_pkt_bytes : bytes
        mutate packet data

    Returns
    -------
    locations : list[tuple[int, str]]
        List of mutation locations. Each item in the list is a tuple consisting of
        **mutation offset** and **value of mutated byte**.
    """
    # TODO: integrate into fuzzlog class, this is wdissector only however
    # Find the different bytes in two packets. There might be multiple differences.
    if len(original_pkt_bytes) != len(mutated_pkt_bytes):
        ae_logger.info("Two packets have different length.")

    if protocol == "bt":
        offset = -4 - 7
    elif protocol == "fiveg":
        offset = 0
    elif protocol == "wifi":
        offset = -9
    else:
        ae_logger.error("Unknown protocol")

    res = []
    loc = 0
    # TODO: currently this is for bluetooth only
    for i, j in zip(original_pkt_bytes, mutated_pkt_bytes):
        if i != j:
            res.append((loc + offset, f"0x{mutated_pkt_bytes[loc]:02x}"))
        loc += 1
    return res


def convert_bytes_to_cpp_array(b: bytes):
    """
    Helper function to convert Python bytes to a C++ array.

    Parameters
    ----------
    b : bytes
        Python bytes

    Returns
    -------
    cpp_array : str
    """
    # Convert b"abcd" to {'0x61', '0x62', '0x63', '0x64'}
    pkt_string = ",".join([hex(i) for i in b])
    return f"{{ {pkt_string} }}"


def split_crash_id(crash_id: str):
    """
    Split crash identifier into smaller parts.

    Parameters
    ----------
    crash_id : str
        Crash identifier

    Returns
    -------
    assert_error : str
        Assert error line in `crash_id`
    guru_error : str | None
        Guru Meditation error line in `crash_id`
    backtrace1 : str
        The first backtrace
    backtrace2 : str | None
        The second backtrace
    """
    # Guru xxx|Backtrace: xxx |Backtrace: xxx
    # Backtrace xxx
    splitted = crash_id.split("|")
    assert_error = splitted[0]
    guru_error = None
    backtrace1 = None
    backtrace2 = None

    if "Guru" in splitted[1]:
        guru_error = splitted[1]
        backtrace1 = splitted[2]
        if len(splitted) == 4:
            backtrace2 = splitted[3]
    else:
        # Backtrace: xxx |Backtrace: xxx
        backtrace1 = splitted[1]
        if len(splitted) == 3:
            backtrace2 = splitted[2]

    backtrace1 = re.sub(r"[^: ]0x", " 0x", backtrace1)
    if backtrace2 is not None:
        backtrace2 = re.sub(r"[^: ]0x", " 0x", backtrace2)

    return assert_error, guru_error, backtrace1, backtrace2


def split_backtrace(bt: str):
    """
    Split backtrace into hex values. The hex values inside the backtrace are
    usually paired and each pair is separated by space like: `0x01:0x02 0x03 0x04`.

    Parameters
    ----------
    bt : str
        Backtrace

    Returns
    -------
    first_hex : list[str]
        List of the first hex values of each pair of the hex value.
    second_hex : list[str]
        List of the second hex values of each pair of the hex value.
    """
    splitted = bt.lstrip("Backtrace: ").lstrip("Backtrace:").split(" ")
    first_hex = []
    second_hex = []
    for i in splitted:
        temp = i.split(":")
        first_hex.append(temp[0])
        second_hex.append(temp[1])

    return first_hex, second_hex


def is_same_backtrace(bt1, bt2, threshold: int, first_hex_mismatch_thresh: int = 1):
    """
    Check if two backtrace are the same.

    The following types of backtrace variations are considered as same backtraces. Note that backtraces consist of pairs, and each pair contains two values.
        1. **Either** value in the first pair mismatches
        bt1 > Backtrace:0x4002c7bd:0x3ffcc540 0x40101311:0x3ffcc580 0x4001a637:0x3ffcc5a0 0x40019d11:0x3ffcc5d0 0x40055b4d:0x3ffcc5f0 0x400fdb3b:0x3ffcc610 0x400fe0fd:0x3ffcc630 0x4009153d:0x3ffcc660
        bt2 > Backtrace:0x40027587:0x3ffcc560 0x40101311:0x3ffcc580 0x4001a637:0x3ffcc5a0 0x40019d11:0x3ffcc5d0 0x40055b4d:0x3ffcc5f0 0x400fdb3b:0x3ffcc610 0x400fe0fd:0x3ffcc630 0x4009153d:0x3ffcc660

        2. **Either** value in the last pair mismatches
        bt1 > Backtrace:0x4002bdbf:0x3ffcc110 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250
        bt2 > Backtrace:0x4002bdbf:0x3ffcc520 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc660

        3. The same difference between the corresponding **second** value in each pair. In the following example, the fixed difference is 0x410
        bt1 > Backtrace:0x4002bdbf:0x3ffcc110 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250
        bt2 > Backtrace:0x4002bdbf:0x3ffcc520 0x40101311:0x3ffcc580 0x4001a637:0x3ffcc5a0 0x40019d11:0x3ffcc5d0 0x40055b4d:0x3ffcc5f0 0x400fdb3b:0x3ffcc610 0x400fe0fd:0x3ffcc630 0x4009153d:0x3ffcc660

        4. Any combination of the types mentioned above.

        TODO: ? should this type be considered as the same crash? The first value in the second last pair is different
        Backtrace:0x40082dcd:0x3ffcc0a0 0x400fd74d:0x3ffcc0c0 0x40019fb5:0x3ffcc0e0 0x400208ed:0x3ffcc110 0x4002c9fa:0x3ffcc130 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009153d:0x3ffcc250|Backtrace:0x4013205f:0x3ffbc470 0x400d38eb:0x3ffbc490 0x400928d5:0x3ffbc4b0 0x4009153d:0x3ffbc4d0
        Backtrace:0x40082dcf:0x3ffcc0a0 0x400fd74d:0x3ffcc0c0 0x40019fb5:0x3ffcc0e0 0x400208ed:0x3ffcc110 0x4002c9fa:0x3ffcc130 0x40101311:0x3ffcc170 0x4001a637:0x3ffcc190 0x40019d11:0x3ffcc1c0 0x40055b4d:0x3ffcc1e0 0x400fdb3b:0x3ffcc200 0x400fe0fd:0x3ffcc220 0x4009140d:0x3ffcc250|Backtrace:0x4013205f:0x3ffbc470 0x400d38eb:0x3ffbc490 0x400927a5:0x3ffbc4b0 0x4009140d:0x3ffbc4d0

    Erroneous backtrace should return False.
        1. Backtrace:XXXX |<-CORRUPTED

    Parameters
    ----------
    bt1 : None | str
        The first backtrace
    bt2 : None | str
        The second backtrace
    threshold : int
        The maximum value of the hex value difference between the two backtraces so that
        the two backtraces can be classified as the same backtrace.
    first_hex_mismatch_thresh : int
        In some scenarios, the two backtraces can be the same backtrace even some first hex values are mismatched.

    Returns
    -------
    is_bt1_bt2_same : bool
    """
    if bt1 is None and bt2 is None:
        return True

    if len(bt1) != len(bt2):
        return False

    # TODO: only for state like: [Crash] Crash detected at state TX / LMP / LMP_encapsulated_payload
    if bt1 == bt2:
        return True
    if ":" not in bt1 or ":" not in bt2:
        return False

    if "<-CORRUPTED" in bt1 or "<-CORRUPTED" in bt2:
        return False

    bt1_first_hex, bt1_second_hex = split_backtrace(bt1)
    bt2_first_hex, bt2_second_hex = split_backtrace(bt2)

    # first_hex needs to be identical for the same crash, however, first value OR last value in first_hex can be different
    # maybe calculate number of different values
    first_hex_mismatch_count = 0
    for idx, i, j in zip(range(len(bt1_first_hex)), bt1_first_hex, bt2_first_hex):
        if i != j and idx != 0 and idx != len(bt1_first_hex) - 1:
            first_hex_mismatch_count += 1

    if first_hex_mismatch_count > first_hex_mismatch_thresh:
        return False

    # second_hex is more complex, they can be different, however, each of them may shift with the same difference.
    # Valid shift that can indicate the same crash
    # bt1_second_hex 0x01 0x06 0x08
    # bt2_second_hex 0x05 0x0a 0x0c  < different is always 0x04
    # Invalid shift
    # bt1_second_hex 0x01 0x06 0x08
    # bt2_second_hex 0x06 0x0a 0x0b  < different is 0x05 0x04 0x03
    differences = []
    for i, j in zip(bt1_second_hex, bt2_second_hex):
        differences.append(abs(int(i, 16) - int(j, 16)))
    # The first difference may vary even in the case of same backtrace
    differences.pop(0)

    # return max(differences) <= threshold and sum(differences) / len(differences) <= 200
    return max(differences) <= threshold and max(differences) == min(differences)


def is_same_corrupted_crash(crash_id1: str, crash_id2: str, threshold: int = 2000):
    """
    Check if two **corrupted** crash identifiers can be classified as the same one.

    Parameters
    ----------
    crash_id1 : str
        The first crash identifier
    crash_id2 : str
        The second crash identifier
    threshold : int, default 2000
        The maximum value of the hex value difference between the two backtraces so that
        the two backtraces can be classified as the same backtrace.

    Returns
    -------
    is_same : bool

    See Also
    --------
    `is_same_crash` for checking the normal crash identifiers.
    """
    if ("<-CORRUPTED" in crash_id1 and "<-CORRUPTED" not in crash_id2) or (
        "<-CORRUPTED" not in crash_id1 and "<-CORRUPTED" in crash_id2
    ):
        return False

    if ("LoadProhibited" in crash_id1 and "StoreProhibited" in crash_id2) or (
        "LoadProhibited" in crash_id2 and "StoreProhibited" in crash_id1
    ):
        return False

    # corrupted crash identifier only has one backtrace
    bt1 = crash_id1.replace(" |<-CORRUPTED", "").split("|")[-1]
    bt2 = crash_id1.replace(" |<-CORRUPTED", "").split("|")[-1]

    return is_same_backtrace(bt1, bt2, threshold, first_hex_mismatch_thresh=0)


def is_same_crash(crash_id1: str, crash_id2: str, threshold: int = 2000):
    """
    Check if two crash identifiers can be classified as the same one.

    Parameters
    ----------
    crash_id1 : str
        The first crash identifier
    crash_id2 : str
        The second crash identifier
    threshold : int, default 2000
        The maximum value of the hex value difference between the two backtraces so that
        the two backtraces can be classified as the same backtrace.

    Returns
    -------
    is_same : bool

    See Also
    --------
    `is_same_corrupted_crash` for checking the **corrupted** crash identifiers.
    """
    # Mainly for ESP32 crashes, because only ESP32 will generate "useful" crash logs with backtraces
    # to help identify and distinguish crashes
    if crash_id1 == crash_id2:
        return True
    if crash_id1 == "not_found" or crash_id2 == "not_found":
        return False
    if ("<-CORRUPTED" in crash_id1) or ("<-CORRUPTED" in crash_id2):
        # TODO: <-CORRUPTED backtrace
        return is_same_corrupted_crash(crash_id1, crash_id2, threshold)
    if "|" not in crash_id1 or "|" not in crash_id2:
        return False

    # bt12 is the second backtrace of crash_id1
    assert_error1, guru_error1, bt11, bt12 = split_crash_id(crash_id1)
    assert_error2, guru_error2, bt21, bt22 = split_crash_id(crash_id2)
    if assert_error1 != "" and assert_error1 == assert_error2:
        return True

    # mainly judge by backtraces
    if bt12 is None and bt22 is not None:
        return False
    if bt12 is not None and bt22 is None:
        return False

    return is_same_backtrace(bt11, bt21, threshold) and is_same_backtrace(bt12, bt22, threshold)


def extract_ts(s: str) -> float:
    """
    Extract and convert timestamp from a string like `[2022-06-22 22:54:46.827969] Guru Meditation Error:`.

    Parameters
    ----------
    s : str
        String that contains a timestamp

    Returns
    -------
    ts : float
        Unix timestamp, in seconds.
        If no `[2022-06-22 22:54:46.827969]`-like string are found in the input, return 0.
    """
    timestamp_re = re.compile(r"^\[.*?\]")
    if len(timestamp_re.findall(s)) == 0:
        return 0
    else:
        dt = datetime.datetime.strptime(timestamp_re.findall(s)[0], "[%Y-%m-%d %H:%M:%S.%f]")
        return dt.timestamp()


#########


def random_string(size: int) -> str:
    """
    Generate a random string consisting of lower case letters and digits.

    Parameters
    ----------
    size : int
        Length of the desired random string

    Returns
    -------
    s : str
        Random string
    """
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(size))


def human_current_date() -> str:
    """
    Generate a human-friendly current date.
    The format is month_day_hour_minute, for example: `10_04_17_05` means `October 4th, 17:05`.

    Parameters
    ----------
    None

    Returns
    -------
    date_str : str
    """
    now = datetime.datetime.now()
    return f"{now.month:02}_{now.day:02}_{now.hour:02}_{now.minute:02}"


def get_logger(name: str) -> logging.Logger:
    """
    Get logger with the specified name.

    Parameters
    ----------
    name : str
        Logger name

    Returns
    -------
    logger : Logger
    """
    # TODO: this function needs to be prevented from being called multiple times

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    log_path = f"{RUN_LOG_PATH}/{name}.log"
    filehandler = logging.FileHandler(log_path, mode="w", encoding="utf8")
    print(f"AirBugCatcher log is saved in {log_path}")
    filehandler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(levelname)s - %(filename)s:%(funcName)s:%(lineno)d - %(message)s"
        )
    )
    logger.addHandler(filehandler)
    return logger


session_id = random_string(4)
ae_logger = get_logger(f"ae_{human_current_date()}_{session_id}")


def calc_bytes_sha256(b: bytes) -> str:
    """
    Calculate sha256 hash value of a bytes object.

    Parameters
    ----------
    b : bytes

    Returns
    -------
    h : str
        sha256 hash value
    """
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(b)

    return hash_sha256.hexdigest()


def calc_file_sha256(file_path: str, chunk_size: int = 4096) -> str:
    """
    Calculate sha256 hash value of a file.

    Parameters
    ----------
    file_path : str
        Path to file
    chunk_size : int, default 4096
        Chunk when reading the file. The chunk will be read into memory.

    Returns
    -------
    sha256_hash : str
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if len(chunk) == 0:
                break
            hash_sha256.update(chunk)

    return hash_sha256.hexdigest()


def pcap_pkt_reader(path: str):
    """
    Capture file reader, using python-pcapng library.

    Parameters
    ----------
    path : str
        Path to the capture file

    Yields
    -------
    packet : EnhancedPacket
    """
    # Return a generator to yield EnhancedPacket and its index in the capture: (index, EnhancedPacket)
    with open(path, "rb") as f:
        scanner = FileScanner(f)
        pkt_index = 0  # this is the packet number in Wireshark
        try:
            for block in scanner:
                if not isinstance(block, EnhancedPacket):
                    continue
                pkt_index += 1
                yield block
        except TruncatedFile:
            ae_logger.info(
                f"The capture file {path} is truncated. This is normal when Wireshark"
                " writes the capture file and does not mean the capture file is"
                " broken."
            )
        except Exception:
            ae_logger.error(
                f"Processing capture file: {path} at packet: {pkt_index}",
                exc_info=True,
            )


Protocol = Literal["fiveg", "bt", "wifi"]


class WDissectorTool:
    """
    WDissector useful tools.

    WDissectorTool class provides easy access to some useful functions developed by WDissector.

    Attributes
    ----------
    protocol : str
        Protocol used in WDissector
    enable_full_dissection : bool
        Enable the full dissection mode of WDissector.
    """

    def __init__(
        self,
        protocol: Protocol,
        decoding_offset: int,
        enable_full_dissection: bool = False,
    ) -> None:
        """
        Initialize WDissector instance.
        """
        self.protocol = protocol
        self.decoding_offset = decoding_offset

        # Configuration files for state machine and model
        if protocol == "bt":
            state_machine_config = BT_WD_SM_CONFIG
            model_config = BT_WD_MODEL_CONFIG
        elif protocol == "fiveg":
            state_machine_config = FIVEG_WD_SM_CONFIG
            model_config = FIVEG_WD_MODEL_CONFIG
        elif protocol == "wifi":
            state_machine_config = WIFI_WD_SM_CONFIG
            model_config = WIFI_WD_MODEL_CONFIG

        self.StateMachine = Machine()
        # Load State Mapper configuration
        if not self.StateMachine.init(state_machine_config):
            ae_logger.error("Error initializing state machine")
            exit(1)
        # Get wdissector instance from state machine initialization
        self.wd = self.StateMachine.wd

        if not self.StateMachine.LoadModel(model_config):
            ae_logger.error("Error loading state machine model")
            exit(1)

        self.PktLabelGen = WDPacketLabelGenerator()
        self.PktLabel = wd_pkt_label()
        # Load State Mapper configuration
        if not self.PktLabelGen.init(state_machine_config, True):
            ae_logger.error("Error initializing packet label generator")
            exit(1)

        # Enable FULL dissection mode if using wd_read_field_by_offset
        if enable_full_dissection:
            wd_set_dissection_mode(self.wd, WD_MODE_FULL)

    def get_pkt_direction(self, pkt: bytes):
        direction = WD_DIR_TX

        try:
            if self.protocol == "bt":
                direction = WD_DIR_TX if pkt[3] == 0 else WD_DIR_RX
            elif self.protocol == "fiveg":
                direction = WD_DIR_TX if pkt[49] == 1 else WD_DIR_RX
        except:
            pass

        return direction

    # TODO Dissect once for all
    def pkt_state(self, pkt: bytes, pkt_decoding_offset: int):
        """
        Get state of a packet.

        Parameters
        ----------
        pkt : bytes
            Packet data in bytes
        pkt_decoding_offset : int
            Offset to decode the packet. In some scenarios, WDissector may
            need to decode a packet from the middle.

        Returns
        -------
        state : str
        """
        # TODO: detect packet direction, which is different for bluetooth and 5g
        direction = self.get_pkt_direction(pkt)
        pkt = bytearray(pkt)[self.decoding_offset :]
        # 1) Prepare State Mapper
        self.StateMachine.PrepareStateMapper(self.wd)
        # 2) Set packet direction (WD_DIR_TX or WD_DIR_RX) and decode packet
        wd_set_packet_direction(self.wd, direction)
        wd_packet_dissect(self.wd, pkt, len(pkt))
        # 3) Run State Mapper
        transition_ok = self.StateMachine.RunStateMapper(
            self.wd, direction == WD_DIR_TX
        )  # 2nd argument force transition to TX state, so we just need to validate RX
        # print(wd_packet_show(self.wd))
        # input()
        return self.StateMachine.GetCurrentStateName()

    def label_pkt(self, pkt: bytes, pkt_decoding_offset: int = 4):
        """
        Get the label of a packet. The label is used to identify a packet and it is
        in the form of Wireshark filter.

        Parameters
        ----------
        pkt : bytes
            Packet data in bytes
        direction : WD_DIR_TX or WD_DIR_RX
            Packet direction
        pkt_decoding_offset : int
            Offset to decode the packet. In some scenarios, WDissector may
            need to decode a packet from the middle.

        Returns
        -------
        label : str

        """
        # Convert to raw and then to bytearray
        # bluetooth classic needs offset 4
        # TODO: pkt_decoding_offset should be set from capture type
        direction = self.get_pkt_direction(pkt)
        pkt = bytearray(pkt)[self.decoding_offset :]
        # Try generating a label for this packet and collect the matched field and value info
        PktLabel = self.PktLabelGen.LabelPacket(direction, pkt, len(pkt))

        if PktLabel.label_status is True:
            return f"{PktLabel.pkt_field_name} == {PktLabel.pkt_field_value}"
        else:
            # logger.warning(f"Cannot label packet {pkt}")
            return None

    def field_offset_bitmask(self, pkt: bytes, field_name: str) -> tuple[int, int, int]:
        """
        Get the location of given field in packet

        Returns
        ------
        bitmask : int
            Field bitmask
        bitmask_offset : int
            Offset of the bitmask
        field_offset : int
            Offset to that field bitmask, from the beginning of packet (after `decoding_offset`)
        """

        direction = self.get_pkt_direction(pkt)

        # Register the field first
        target_wd_field = wd_field(field_name)
        if not target_wd_field:
            ae_logger.error(f"Field not valid: {field_name}")
            raise Exception(f"Field not valid: {field_name}")

        wd_register_field(self.wd, target_wd_field)

        pkt = bytearray(pkt)[self.decoding_offset :]
        wd_set_packet_direction(self.wd, direction)
        wd_packet_dissect(self.wd, pkt, len(pkt))

        target_field = wd_read_field(self.wd, target_wd_field)
        if target_field:
            bitmask = packet_read_field_bitmask(target_field)
            field_size = packet_read_field_size(target_field)  # in bytes
            bitmask_offset = packet_read_field_bitmask_offset(bitmask)
            field_offset = packet_read_field_offset(target_field)
            # In WDissector, if the field spans the whole bytes, the returned bitmask is 0
            if bitmask == 0:
                bitmask = 2 ** (field_size * 8) - 1

            return bitmask, bitmask_offset, field_offset, field_size
        else:
            ae_logger.error(f"something wrong in wd_read_field: field: {field_name}")
            raise Exception(f"something wrong in wd_read_field: field: {field_name}")

    def decode_pkt(self, pkt: bytes):
        direction = self.get_pkt_direction(pkt)
        pkt = bytearray(pkt)[self.decoding_offset :]
        # 1) Prepare State Mapper
        self.StateMachine.PrepareStateMapper(self.wd)
        # 2) Set packet direction (WD_DIR_TX or WD_DIR_RX) and decode packet
        wd_set_packet_direction(self.wd, direction)
        wd_packet_dissect(self.wd, pkt, len(pkt))

        # print(wd_packet_summary(self.wd))
        print(wd_packet_show(self.wd))

    def test_func(self, pkt: bytes):
        pass


def bytes_to_cpp_array(b: bytes):
    """
    Helper function to convert Python bytes to a C++ array.

    Parameters
    ----------
    b : bytes
        Python bytes

    Returns
    -------
    cpp_array : str
    """
    # Convert b"abcd" to {0x61, 0x62, 0x63, 0x64}
    pkt_string = ",".join([hex(i) for i in b])
    return f"{{ {pkt_string} }}"


def is_packet_logger(b: bytes):
    """
    Check if the packet contains packetlogger layer like:
    `[Crash] Crash detected` or `Iteration: 140`
    """
    return b.startswith(b"\x0a")


def extract_keys(d: dict, only_deepest_keys: bool = False):
    """
    Traverse a dictionary **recursively** and return all **keys** in all levels as a set.
    Identical keys in different levels are returned only once.

    {
        "a": 1,             << deepest key
        "b": {              << not deepest key
            "aa": 2,        << deepest key
            "ab": 3         << deepest key
        }
    }
    """
    res = set()
    for k, v in d.items():
        if isinstance(v, dict):
            if not only_deepest_keys:
                res.add(k)

            res.update(extract_keys(v))
        elif isinstance(v, list):
            for i in v:
                if not only_deepest_keys:
                    res.add(k)
                if isinstance(i, dict):
                    res.update(extract_keys(i))
        else:
            res.add(k)

    return res


def flatten_dict(d: dict):
    res = {}
    for k, v in d.items():
        if isinstance(v, dict):
            res.update(flatten_dict(v))
        else:
            res[k] = v

    return res


def discover_crashes_wdissector(
    protocol: Protocol, capture_path: str, decoding_offset: int
) -> list[Crash]:
    """
    Find all crashes inside the capture file which is generated by WDissector.

    Parameters
    ----------
    protocol : str
        Protocol used in the capture
    capture_path : str
        File path to the capture file
    decoding_offset : int
        Packet decoding offset used in WDissector

    Returns
    -------
    crashes : list[Crash]
        List of crashes inside the capture file
    """
    wd_tool = WDissectorTool(protocol, decoding_offset)
    # logger.info("Start capture crashes discovery...")
    # Cache logic, hack method, see comments above
    crashes: list[Crash] = []
    fuzzed_pkts: list[FuzzedPkt] = []
    pkts: list[Pkt] = []
    prev_pkt_bytes: bytes
    crash_idx = 0
    current_iteration = 1  # iteration starts from 1
    for pkt_summary, pyshark_pkt, pkt in packet_dissection_reader(capture_path, True, True, True):
        # zip(
        #     pcap_pkt_reader(capture_path),
        #     packet_summary_reader(capture_path, only_summaries=True),
        #     packet_summary_reader(capture_path, only_summaries=False, use_json=True),
        # ):
        pkt_comment = pkt.options.get("opt_comment")
        # mutated packet
        if "Fuzzed from previous" in pkt_comment:
            # field_name = packet_mutated_field(prev_packet_bytes, packet.packet_data) # KEEP
            fuzzed_pkts.append(
                FuzzedPkt(
                    pkt_bytes=pkt.packet_data,
                    loc=int(pkt_summary["No."]),
                    iteration=current_iteration,
                    state=wd_tool.pkt_state(prev_pkt_bytes, decoding_offset),
                    filter=wd_tool.label_pkt(prev_pkt_bytes, decoding_offset),
                    type="mutation",
                    fuzz_info=None,
                    prev_pkt_bytes=prev_pkt_bytes,
                )
            )
        # duplicated packet
        elif pkt_comment is not None and "Duplicated" in pkt_comment:
            fuzzed_pkts.append(
                FuzzedPkt(
                    pkt_bytes=pkt.packet_data,
                    loc=int(pkt_summary["No."]),
                    iteration=current_iteration,
                    state=wd_tool.pkt_state(pkt.packet_data, decoding_offset),
                    filter=wd_tool.label_pkt(pkt.packet_data, decoding_offset),
                    type="duplication",
                    fuzz_info=None,
                    prev_pkt_bytes=prev_pkt_bytes,
                )
            )
        elif b"[Crash]" in pkt.packet_data or b"[Timeout]" in pkt.packet_data:
            if b"Original [Timeout]" in pkt.packet_data:
                # In some 5G captures, there are some "fake" timeout indication
                pass
            elif False and len(fuzzed_pkts) == 0:
                # sometimes two crashes are too close, no fuzzed packets for the second crash
                # skip this crash
                pass
            else:
                if b"[Crash]" in pkt.packet_data:
                    crash_type = "normal"
                else:
                    crash_type = "timeout"

                for _pkt in pkts:
                    _pkt.state = wd_tool.pkt_state(_pkt.pkt_bytes, decoding_offset)
                    _pkt.filter = wd_tool.label_pkt(_pkt.pkt_bytes, decoding_offset)

                crashes.append(
                    Crash(
                        fuzzed_pkts=fuzzed_pkts[:],
                        pkts=pkts[:],
                        loc=int(pkt_summary["No."]),
                        iteration=current_iteration,
                        identifier=None,
                        crash_type=crash_type,
                        raw=pkt.packet_data,
                        timestamp=pkt.timestamp,
                    )
                )
                crash_idx += 1

            fuzzed_pkts = []
            pkts = []
        elif b"Iteration" in pkt.packet_data:
            current_iteration += 1

        # Store all packets
        if (not is_packet_logger(pkt.packet_data[decoding_offset:])) and pkt_summary[
            "Protocol"
        ] != "PKTLOG":
            # get all fields
            fields = {}
            for layer in pyshark_pkt.layers:
                if layer.layer_name in ["pkt_comment", "eth", "udp", "ip"]:
                    continue

                fields.update(flatten_dict(layer._all_fields))

            # here _pkt means the real packets, not packet loggers
            _pkt = Pkt(
                pkt_bytes=pkt.packet_data,
                loc=int(pkt_summary["No."]),
                iteration=current_iteration,
                # state=wd_tool.pkt_state(pkt.packet_data, decoding_offset),
                # filter=wd_tool.label_pkt(pkt.packet_data, decoding_offset),
                state=None,  # To be filled when storing crash
                filter=None,
                info=pkt_summary["Info"],
                fields=fields,
                comment=pkt.options.get("opt_comment"),
            )
            if pkt_comment == "Fuzzed from previous":
                # remove the previous packet which is not sent out actually
                pkts.pop()

            pkts.append(_pkt)

        # hey, no need to store all packets which might be a lot, especially for 5G
        num_iter_store = 10
        if len(fuzzed_pkts) > 0 and current_iteration - fuzzed_pkts[0].iteration > num_iter_store:
            # pop the earlist iteration
            for to_pop_idx, to_pop in enumerate(fuzzed_pkts):
                if current_iteration - to_pop.iteration <= num_iter_store:
                    break

            fuzzed_pkts = fuzzed_pkts[to_pop_idx:]
        if len(pkts) > 0 and current_iteration - pkts[0].iteration > num_iter_store:
            # pop the earlist iteration
            for to_pop_idx, to_pop in enumerate(pkts):
                if current_iteration - to_pop.iteration <= num_iter_store:
                    break

            pkts = pkts[to_pop_idx:]

        prev_pkt_bytes = pkt.packet_data

        if int(pkt_summary["No."]) % 10000 == 0:
            ae_logger.info(f"Processed {pkt_summary['No.']} packets.")

    return crashes


class PDMLPacketReader:
    """
    Read packet from PDML document
    This is currently optimized for the capture generated by WDissector
    """

    def __init__(self, capture_path: str) -> None:
        self.capture_path = capture_path

        pdml = subprocess.check_output(
            [TSHARK_PATH, "-CWDissector", "-Tpdml", f"-r{self.capture_path}"],
            cwd="/home/wireless-deep-fuzzer",
        )
        self.tree = ET.parse(BytesIO(pdml))

    def read_field(self, field: Element):
        res = {}
        if field.attrib.get("hide", None) == "yes":
            return res

        sub_fields = field.findall("./field")
        if len(sub_fields) == 0:
            key = field.attrib["name"]
            if key == "":
                key = field.attrib["show"]
            res[key] = field.attrib["showname"]
        else:
            key = field.attrib["name"]
            if key == "":
                key = field.attrib["show"]

            res[key] = {}
            for sub_field in sub_fields:
                for k, v in self.read_field(sub_field).items():
                    res[key][k] = v

        return res

    def read_proto(self, proto: Element):
        res = {}
        if proto.attrib.get("hide", None) == "yes":
            return res

        for tree in proto.findall("./"):
            if tree.tag == "field":
                for k, v in self.read_field(tree).items():
                    res[k] = v
            elif tree.tag == "proto":
                res[tree.attrib["name"]] = self.read_proto(tree)
        return res

    def read(self):
        for packet in self.tree.findall("./packet"):
            fields = {}
            for proto in packet.findall("./"):
                # if proto.attrib["name"] in ["frame", "eth", "ip", "udp"]:
                # continue
                pkt_num = 0
                if proto.attrib["name"] == "geninfo":
                    for field in proto.findall("./field"):
                        if field.attrib["name"] == "num":
                            pkt_num = int(field.attrib["show"])
                            break
                else:
                    fields[proto.attrib["name"]] = self.read_proto(proto)

                # res[proto.attrib["name"]] = read_proto(proto)

            yield fields
            # print(res)
            # print(fields)
            # input()


PacketSummary = TypedDict(
    "PacketSummary",
    {
        "No.": str,
        "Time": str,
        "Source": str,
        "Destination": str,
        "Protocol": str,
        "Length": str,
        "Info": str,
    },
)


@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[True],
    include_detailed_dissection: Literal[False],
    include_raw: Literal[False],
) -> Generator[tuple[PacketSummary], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[False],
    include_detailed_dissection: Literal[True],
    include_raw: Literal[False],
) -> Generator[tuple[PysharkPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[False],
    include_detailed_dissection: Literal[False],
    include_raw: Literal[True],
) -> Generator[tuple[EnhancedPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[True],
    include_detailed_dissection: Literal[True],
    include_raw: Literal[False],
) -> Generator[tuple[PacketSummary, PysharkPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[False],
    include_detailed_dissection: Literal[True],
    include_raw: Literal[True],
) -> Generator[tuple[PysharkPacket, EnhancedPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[True],
    include_detailed_dissection: Literal[False],
    include_raw: Literal[True],
) -> Generator[tuple[PacketSummary, EnhancedPacket], Any, None]: ...
@overload
def packet_dissection_reader(
    capture_path: str,
    include_info: Literal[True],
    include_detailed_dissection: Literal[True],
    include_raw: Literal[True],
) -> Generator[tuple[PacketSummary, PysharkPacket, EnhancedPacket], Any, None]: ...
def packet_dissection_reader(
    capture_path: str,
    include_info: bool = True,
    include_detailed_dissection: bool = False,
    include_raw: bool = False,
):
    """
    Help function to return the packet dissection information generated by Wireshark
    return what wireshark shows (small computation cost), additionally fields info, packet comment, raw packet
    """
    tshark_params = {"-C": "WDissector"}
    readers = []
    if include_info:
        info_reader = pyshark.FileCapture(
            capture_path,
            tshark_path=TSHARK_PATH,
            only_summaries=True,
            keep_packets=False,
            use_json=False,
            custom_parameters=tshark_params,
        )
        info_fields_reader = (i._fields for i in info_reader)
        readers.append(info_fields_reader)
    if include_detailed_dissection:
        # detail_reader = pyshark.FileCapture(
        #     capture_path,
        #     tshark_path=TSHARK_PATH,
        #     only_summaries=False,
        #     keep_packets=False,
        #     # use_json=True,
        #     use_ek=False,
        #     custom_parameters=tshark_params,
        # )
        pdml_reader = PDMLPacketReader(capture_path)
        readers.append(pdml_reader.read())
    if include_raw:
        pcap_reader = pcap_pkt_reader(capture_path)
        readers.append(pcap_reader)

    yield from zip(*readers)


def get_packet_direction(pkt_bytes: bytes, protocol: ProtocolType):
    # TX: central send
    # RX: device send
    if protocol == "bt":
        return pkt.info[:2]
    else:
        # 5G
        return "TX" if pkt_bytes[50] == 1 else "RX"


if __name__ == "__main__":
    # for i in packet_dissection_reader(
    #     "captures/esp32_bt/capture_bluetooth.pcapng", True, True, True
    # ):
    #     print(1)

    # fuzzed_pkts = [
    #     {"type": "dup", "filter": "xx", "data": [12, 45]},
    #     {"type": "mut", "filter": "xxy", "mutations": [(4, "0xd2")]},
    # ]
    # print(gen_universal_exploit_script(fuzzed_pkts))
    # crash1 = "|Guru Meditation Error: Core  1 panic'ed (StoreProhibited). Exception was unhandled.|Backtrace:0x4000c2a0:0x3ffc78300x400de36b:0x3ffc7840 0x400fca3e:0x3ffc7860 0x400fd6fa:0x3ffc7880 0x400fdac1:0x3ffc78a0 0x400fe37a:0x3ffc78c0 0x400fe412:0x3ffc78f0 0x400fe466:0x3ffc7910 0x400fe8b6:0x3ffc7930 0x400de770:0x3ffc7950 0x400e209a:0x3ffc7e20 0x400e111d:0x3ffc7e50 0x400e1501:0x3ffc7eb0 0x400dde5b:0x3ffc7f20 0x400ddfcf:0x3ffc7f50 0x400de0c3:0x3ffc7f70 0x4008b589:0x3ffc7fa0"
    # crash2 = "|Guru Meditation Error: Core  1 panic'ed (StoreProhibited). Exception was unhandled.|Backtrace:0x4000c2b7:0x3ffd1c400x400de36b:0x3ffd1c50 0x400fca3e:0x3ffd1c70 0x400fd6fa:0x3ffd1c90 0x400fdac1:0x3ffd1cb0 0x400fe37a:0x3ffd1cd0 0x400fe412:0x3ffd1d00 0x400fe466:0x3ffd1d20 0x400fe8b6:0x3ffd1d40 0x400de770:0x3ffd1d60 0x400e209a:0x3ffd2230 0x400e111d:0x3ffd2260 0x400e1501:0x3ffd22c0 0x400dde5b:0x3ffd2330 0x400ddfcf:0x3ffd2360 0x400de0c3:0x3ffd2380 0x4008b589:0x3ffd23b0"
    # print(is_same_crash(crash1, crash2, 50000))
    # print(is_same_crash(crash1, crash2, 2000))

    for (eh_pkt,) in packet_dissection_reader(
        "captures/esp32-bt/dup/t1/capture_bluetooth_no_original.pcapng",
        include_info=False,
        include_detailed_dissection=False,
        include_raw=True,
    ):
        print(eh_pkt.packet_data[:8].hex())

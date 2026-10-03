from dataclasses import dataclass
from typing import Literal

BoardType = Literal["esp32", "cypress", "oneplus"]
ProtocolType = Literal["fiveg", "bt", "wifi"]
PcapPromptMode = Literal["full", "diff", "full+context", "diff+context"]


class Crash:
    """
    Crash class contains the information and packets related to a crash.

    Attributes
    ----------
    fuzzed_pkts : list["FuzzedPkt"]
        List of fuzzed packets before the crash (and after the last crash) from the fuzzing logs
    pkts : list["Pkt"]
        List of packets (both normal and fuzzed) before the crash (and after the last crash) from the fuzzing logs
    loc : int
        Location of crash in fuzzing logs
    iteration : int
        Iteration of crash in fuzzing logs
    identifier : str | None
        Identifier of crash
    crash_type : str
        Type of crash, possible values are `normal`, `timeout` and `flooding`
    raw : bytes
        Raw string of crash comment
    timestamp : int
        Timestamp when crash happens
    """

    def __init__(
        self,
        fuzzed_pkts: list["FuzzedPkt"],
        pkts: list["Pkt"],
        loc: int,
        iteration: int,
        identifier: str | None,
        crash_type: str,
        raw: bytes,
        timestamp: int,
    ) -> None:
        self.fuzzed_pkts = fuzzed_pkts  # this should be in ascending order by "loc" key
        self.pkts = pkts
        self.loc = loc
        self.iteration = iteration
        self.identifier = identifier
        self.type = crash_type
        self.raw = raw
        self.timestamp = timestamp


@dataclass
class FuzzedPkt:
    """
    FuzzedPkt class contains the information of one fuzzed packet in fuzzing log.
    """

    pkt_bytes: bytes
    loc: int
    iteration: int
    state: str
    filter: str | None
    type: Literal["mutation", "duplication"]
    fuzz_info: dict | None
    prev_pkt_bytes: bytes


@dataclass
class Pkt:
    loc: int
    iteration: int
    state: str
    filter: str | None
    info: str
    fields: dict


PromptType = Literal["root_cause", "check_attack"]

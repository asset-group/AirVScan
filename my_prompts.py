import copy
import json
from typing import Literal, TypedDict

from json_flatten import flatten, unflatten
from my_prompts_check_attack import (
    check_attack_prompt_bt,
    check_attack_prompt_fiveg,
    check_attack_prompt_modbus,
)
from my_prompts_find_attack_vector import (
    find_attack_vector_prompt_bt,
    find_attack_vector_prompt_fiveg,
    find_attack_vector_prompt_modbus,
)
from rag_utils import DocSearch
from utils import Pkt, extract_keys
from utils_types import PcapPromptMode, PromptType, ProtocolType


class ChangedFields(TypedDict):
    diff: dict[str, set]
    deletion: dict[str, set]
    noref: dict[str, set]


def find_changed_fields(pkts: list[Pkt]):
    # Store the values of all fields under each packet filter. For example:
    # {
    # "TX|btbrlmp.op==3": {
    #     "field1": [1,2,3],
    #     "field2":[1,2,2,2,3]
    #     }
    # }
    pkt_stat = {}
    # Store packet count by packet filter
    pkt_filter_stat = {}

    for pkt in pkts:
        pkt_filter_stat[pkt.filter] = pkt_filter_stat.get(pkt.filter, 0) + 1

        # Initialize
        if pkt.filter not in pkt_stat:
            pkt_stat[pkt.filter] = {}

        pkt_fields_copy = copy.deepcopy(pkt.fields)
        replace_key(pkt_fields_copy, ".", "|")
        fields_flattened = flatten(pkt_fields_copy)
        for field, value in fields_flattened.items():
            if field not in pkt_stat[pkt.filter]:
                pkt_stat[pkt.filter][field] = []

            pkt_stat[pkt.filter][field].append(value)

    # Three cases of field change:
    #   1. diff: different values of a field are observed
    #   2. deletion: field is missing in some packets
    #   3. noref: only one packet with that filter is in the packet, we need to include that packet
    changed_res: ChangedFields = {
        "diff": {},
        "deletion": {},
        "noref": {},
    }  # {<filter>: <changed_fields>}

    for f, field_values in pkt_stat.items():
        # Packets that are only observed once
        if pkt_filter_stat[f] == 1:
            # noref case
            changed_res["noref"][f] = set(field_values.keys())
        else:
            for field, values in field_values.items():
                num_unique = len(set(values))
                num = len(values)

                # diff case
                if num_unique >= 2:
                    if f not in changed_res["diff"]:
                        changed_res["diff"][f] = set()
                    changed_res["diff"][f].add(field)
                # deletion case
                if num < pkt_filter_stat[f]:
                    if f not in changed_res["deletion"]:
                        changed_res["deletion"][f] = set()
                    changed_res["deletion"][f].add(field)

    changed_res_flatten = {}
    for case, filter_fields in changed_res.items():
        for f, fields in filter_fields.items():
            if f not in changed_res_flatten:
                changed_res_flatten[f] = set()

            changed_res_flatten[f].update(fields)

    return changed_res, changed_res_flatten


def replace_key(d: dict | list | tuple, old: str, new: str):
    if isinstance(d, dict):
        keys = list(d.keys())
        for k in keys:
            if isinstance(d[k], (dict, list, tuple)):
                replace_key(d[k], old, new)
            d[k.replace(old, new)] = d.pop(k)
    else:
        for i in d:
            if isinstance(i, (dict, list, tuple)):
                replace_key(i, old, new)


def remove_unchanged_fields(pkts: list[Pkt]):
    changed_fields, changed_fields_flatten = find_changed_fields(pkts)
    for idx in range(len(pkts)):
        replace_key(pkts[idx].fields, ".", "|")
        pkts[idx].fields = flatten(pkts[idx].fields)
        # print(changed_fields_flatten[pkts[idx].filter], pkts[idx].fields)
        # input()

        if pkts[idx].filter in changed_fields_flatten:
            for field in list(pkts[idx].fields.keys()):
                if field not in changed_fields_flatten[pkts[idx].filter]:
                    del pkts[idx].fields[field]

        pkts[idx].fields = unflatten(pkts[idx].fields)
        replace_key(pkts[idx].fields, "|", ".")

    # Now prepare changed fields prompt
    changed_fields_friendly = copy.deepcopy(changed_fields)
    for case, filter_fields in changed_fields_friendly.items():
        for f, fields in filter_fields.items():
            _fields = set()
            for field in fields:
                _fields.add(field.split(".")[-1].replace("|", "."))

            filter_fields[f] = _fields

    changed_fields_slot = "Please focus on these fields during your analysis. The fields are grouped into filters. \n"

    changed_fields_slot += f"These fields are observed to occur with different values during the packet sequence, you can pay more attention to these fields: {changed_fields_friendly['diff']}\n"
    changed_fields_slot += f"These fields are observed to occur only in some packets of a certain filter during the packet sequence: {changed_fields_friendly['deletion']}\n"
    changed_fields_slot += f"These fields are observed to occur in a packet which is only present once during the packet sequence : {changed_fields_friendly['noref']}\n"

    return changed_fields_slot


def prepare_context(all_fields, protocol: ProtocolType):
    # Field glossary
    if protocol == "bt":
        with open("glossary/bt_fields_glossary.json", "r", encoding="utf8") as f:
            glossary_dict = json.load(f)
    elif protocol == "fiveg":
        with open("glossary/fiveg_fields_glossary.json", "r", encoding="utf8") as f:
            glossary_dict = json.load(f)
    else:
        glossary_dict = {}
    glossary = {k: glossary_dict.get(k) for k in all_fields}

    # Field description, which is more detailed and informational than glossary
    if protocol == "bt":
        with open("glossary/bt_fields_desc.json", "r", encoding="utf8") as f:
            desc_dict = json.load(f)
    elif protocol == "fiveg":
        with open("glossary/fiveg_fields_desc.json", "r", encoding="utf8") as f:
            desc_dict = json.load(f)
    else:
        desc_dict = {}

    desc = {}
    for k in all_fields:
        v = desc_dict.get(k)
        if v is not None:
            desc[k] = v
    # desc = {k: desc_dict.get(k) for k in all_fields}

    documents = set()
    doc_search = DocSearch("milvus_demo.db")
    for i in all_fields:
        docs = doc_search.search(protocol, i, 3)
        if len(docs) == 0:
            if glossary.get(i):
                docs = doc_search.search(protocol, glossary[i], 2)

        for doc in docs:
            documents.add(doc)

    contexts_slot = (
        f"These fields descriptions might be useful for your analysis: \n<desc>\n{desc}\n</desc>\n"
    )

    contexts_slot += "\n\nThese documents might be useful for your analysis:"
    for doc in documents:
        contexts_slot += f"\n<doc>\n{doc}\n</doc>"

    return contexts_slot


def get_guidance_prompt(
    pkts: list[Pkt],
    max_iteration: int,
    protocol: ProtocolType,
    pcap_prompt_mode: PcapPromptMode,
    prompt_type: PromptType,
):
    #
    # full: provide all packet fields, which may exceed the LLM context window < no glossary
    # full + context
    # diff: provide only changed packet fields  < no glossary
    # diff + context
    #   Note: <context> means field desc/glossary + documents

    # diff+changed field: +explicit mention about what fields are changed
    # diff+changed field&desc: +and changed fields corresponding explanations
    # context: +contexts

    # ===================== #
    # Packets preprocessing #
    # ======================#
    _pkts = []
    for pkt in pkts:
        # TODO: for 5G, we need to dispose some of the unnecessary packets
        # like UL-SCH or DL-SCH. Though this might cause some issues because this kind
        # of packets are indeed fuzzed during the fuzzing session.
        if protocol == "fiveg":
            if "UL-SCH" in pkt.info:
                continue
            if "[DATA]" in pkt.info:
                continue

        # These layers are not helpful in analysis in our experiments
        for layer in ["eth", "frame", "pkt_comment", "udp", "ip"]:
            if layer in pkt.fields:
                del pkt.fields[layer]

        _pkts.append(pkt)

    pkts = _pkts

    # ===================== #
    # Remove unchanged fields   #
    # ======================#
    # This needs to be done before truncating packets
    changed_fields_slot = ""
    if pcap_prompt_mode.startswith("diff"):
        changed_fields_slot = remove_unchanged_fields(pkts)

    # ===================== #
    # Truncate packets  #
    # ======================#
    pkts_by_iteration = {}
    for pkt in pkts:
        if pkts_by_iteration.get(pkt.iteration) is None:
            pkts_by_iteration[pkt.iteration] = []
        pkts_by_iteration[pkt.iteration].append(pkt)

    pkts_to_be_analyzed = []
    for iteration in list(reversed(pkts_by_iteration.keys()))[:max_iteration]:
        # try from the last iteration
        pkts_to_be_analyzed = pkts_by_iteration[iteration] + pkts_to_be_analyzed
    pkts = pkts_to_be_analyzed

    # Prepare packet sequence
    packet_sequence = []
    all_fields = set()
    for pkt in pkts:
        packet_sequence.append(
            {
                "pkt_filter": pkt.filter,
                "pkt_state": pkt.state,
                "iteration": pkt.iteration,
                "pkt_loc": pkt.loc,
                "pkt_info": pkt.info,
                "pkt_fields": pkt.fields,
            }
        )
        all_fields.update(extract_keys(pkt.fields, only_deepest_keys=False))

        if protocol == "modbus":
            all_fields.add(pkt.info)

    contexts_slot = ""
    if "context" in pcap_prompt_mode:
        contexts_slot = prepare_context(all_fields, protocol)

    packet_sequence = [str(i) for i in packet_sequence]

    # Get prompt template
    if prompt_type == "root_cause":
        if protocol == "bt":
            prompt_template = find_attack_vector_prompt_bt
        elif protocol == "fiveg":
            prompt_template = find_attack_vector_prompt_fiveg
        elif protocol == "modbus":
            prompt_template = find_attack_vector_prompt_modbus

    elif prompt_type == "check_attack":
        if protocol == "bt":
            prompt_template = check_attack_prompt_bt
        elif protocol == "fiveg":
            prompt_template = check_attack_prompt_fiveg
        elif protocol == "modbus":
            prompt_template = check_attack_prompt_modbus
    else:
        print(f"Error: wrong prompt_type: {prompt_type}")

    prompt = prompt_template.format(
        packet_sequence="\n".join(packet_sequence),
        changed_fields_slot=changed_fields_slot,
        contexts_slot=contexts_slot,
    )

    return prompt


if __name__ == "__main__":
    test = {"nr-rrc.asd": "asd", "nr-rrc.a": (1, 2, (2, 3, {"nr-rrc.asdasdasd": 123}))}
    replace_key(test, ".", "|")

    print(test)

"""
Verify the correctness of LLM responses.
This is not for validating the reasoning part of LLM response.
"""

import json
import re
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from llm_utils import Stage1Res
from prompts.my_prompts_check_attack import CheckAttackRes

BASE_DIR = PROJECT_ROOT

with open(BASE_DIR / "obfuscate_dict.json", "rb") as f:
    obfuscate_dict = json.load(f)


def verify_benign(llm_res):
    """
    Verify benign cases which are simpler.
    Note that there are no root_cause prompts for benign cases
    Correct: LLM thinks there is no problems inside the test case
    Wrong: LLM thinks there is something wrong inside the test case
    """
    pass


def verify_root_cause(llm_res: Stage1Res, prompt, prompt_type, prompt_path, case_type, protocol):
    # reason
    reason_path = Path(prompt_path).parent.parent.parent.parent / "reason.json"
    with open(reason_path, "r") as f:
        reason = json.load(f)

    target_filter = reason.get("filter")
    target_reason = reason.get("reason")
    target_pkt_loc = reason.get("pkt_loc")

    # {'pkt_filter': 'TX|btbrlmp.eop == 3', 'pkt_state': 'TX / LMP / LMP_features_req_ext', 'iteration': 1, 'pkt_loc': 5, 'pkt_info': 'TX -
    if target_filter == "":
        print("Please check", prompt_path)
        input()

    reason_type = case_type  # dup, mut, benign, reorder
    # modbus got another kind of malicious packet: reorder
    if "reorder" in prompt_path:
        reason_type = "reorder"

    for abnormal_pkt in llm_res.abnormal_packets:
        pkt_loc = abnormal_pkt.pkt_loc
        # get packet filter
        filter = ""
        for line in prompt.split("\n"):
            match = re.search(r"'pkt_loc':\s*(\d+)", line)
            if match and match.group(1) == str(pkt_loc):
                pkt_filter_match = re.search(r"'pkt_filter':\s*'([^']+)'", line)
                if pkt_filter_match:
                    filter = pkt_filter_match.group(1)
                    break

        if reason_type == "dup" and abnormal_pkt.type == "duplicated":
            # There are only 2 cases of this type, one in esp32-bt and another in oneplus-fiveg
            if target_pkt_loc == pkt_loc or filter == target_filter:
                return True
        elif reason_type == "mut" and abnormal_pkt.type == "mutated":
            if target_pkt_loc == pkt_loc or filter == target_filter:
                target_reason = set([i[0] for i in target_reason])
                if protocol == "modbus":
                    # need to use the obfuscated name
                    target_reason = [obfuscate_dict.get(i, i) for i in target_reason]

                for field in abnormal_pkt.fields:
                    _field = field.field.replace("nr-rrc.", "")
                    try:
                        target_reason.remove(_field)
                    except (KeyError, ValueError):
                        pass

                if len(target_reason) == 0:
                    return True
        elif reason_type == "reorder" and abnormal_pkt.type == "reordered":
            # reorder only exists in modbus
            for pair_locs in abnormal_pkt.reordered_pkt_locs:
                if set(pair_locs) == set(target_pkt_loc):
                    return True

    return False


def verify(db_path: str = "llm_res_final.sqlite3", case_type_filter: str = ""):
    db_conn = sqlite3.connect(db_path)
    db_cursor = db_conn.cursor()
    db_write_cursor = db_conn.cursor()

    query = "select * from llm_res"
    params = ()
    if case_type_filter:
        query += " where case_type = ?"
        params = (case_type_filter,)

    for row in db_cursor.execute(query, params):
        (
            row_id,
            exp_id,
            device,
            protocol,
            case_type,
            n_field,
            noise_type,
            prompt_type,  # check_attack / root_cause
            prompt_mode,  # full / full+context / diff / diff+context
            prompt_path,
            model,
            prompt,
            prompt_hash,
            trial_idx,
            ref_id,
            res,
            res_correct,
            reasoning_correct,
        ) = row
        verify_result = False
        if row_id % 500 == 0:
            print(f"Processing {row_id}...")

        if prompt_type == "check_attack":
            # simpler scenario
            llm_res = CheckAttackRes.model_validate_json(res)
            is_attack = case_type != "benign"
            if llm_res.has_attack == is_attack:
                verify_result = True
            else:
                verify_result = False
        elif prompt_type == "root_cause":
            llm_res = Stage1Res.model_validate_json(res)
            verify_result = verify_root_cause(
                llm_res, prompt, prompt_type, prompt_path, case_type, protocol
            )
        else:
            print(f"Unknown prompt_type: {prompt_type}")

        db_write_cursor.execute(
            "update llm_res set res_correct=? where id=?", (verify_result, row_id)
        )
    # Remember to close database properly
    db_conn.commit()
    db_conn.close()


if __name__ == "__main__":
    verify(str(BASE_DIR / "llm_res_final.sqlite3"))

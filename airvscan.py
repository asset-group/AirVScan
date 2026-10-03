import os
import sqlite3
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor

import nest_asyncio

from llm_utils import Stage1Res, count_token, structured_query
from prompts.my_prompts_check_attack import CheckAttackRes
from utils import calc_file_sha256

nest_asyncio.apply()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def exceed_token_limit(prompt, llm_model):
    max_token_by_model = {
        "grok-4": 256 * 1000,
        "o3-2025-04-16": 200 * 1000,
        "gemini-2.5-pro": 1000 * 1000,
        "gemini-2.5-pro-thinking-8192": 1000 * 1000,
    }
    count = count_token(prompt)
    completion_length = 10000
    buffer = 1000

    return completion_length + count + buffer >= max_token_by_model.get(llm_model, 200 * 1000)


class RunHelper:
    def __init__(
        self,
        db_path: str,
        device,
        protocol,
        case_type,
        n_field,
        models,
        num_trial,
        num_thread,
        exp_id,
    ) -> None:
        self.db_path = db_path
        self.device = device
        self.protocol = protocol
        self.case_type = case_type
        self.n_field = n_field
        self.models = models
        self.num_trial = num_trial
        self.num_thread = num_thread
        self.exp_id = exp_id

        parts = [f"{device}-{protocol}", case_type]
        if n_field:
            parts.append(n_field)
        self.captures_folder = os.path.join(BASE_DIR, "captures", *parts)

        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.read_cursor = self.db.cursor()
        self.read_cursor_lock = threading.Lock()
        self.write_cursor = self.db.cursor()
        self.write_cursor_lock = threading.Lock()

    def prompt_has_res(self, prompt_hash, model, trial_idx):
        with self.read_cursor_lock:
            cursor = self.read_cursor.execute(
                "select id from llm_res where exp_id = ? and prompt_hash = ? and model = ? and trial_idx = ? and res != ''",
                (self.exp_id, prompt_hash, model, trial_idx),
            )
            res = cursor.fetchall()
            if len(res) == 0:
                return False, 0
            else:
                return True, res[0][0]

    def save_res(self, prompt_path: str, model, prompt, prompt_hash, trial_idx, ref_id, res):
        noise_type = "normal" if "/normal" in prompt_path else "noise"
        prompt_type = "check_attack" if "check_attack" in prompt_path else "root_cause"
        prompt_mode = prompt_path.split("/")[-1].split(".")[0]

        print("Save res...")
        with self.write_cursor_lock:
            self.write_cursor.execute(
                "insert into llm_res "
                "(exp_id, device, protocol, case_type, n_field, noise_type,"
                "prompt_type, prompt_mode, prompt_path, model, prompt, prompt_hash, "
                "trial_idx, ref_id, res) values ("
                "?, ?, ?, ?, ?, ?,"
                "?, ?, ?, ?, ?, ?,"
                "?, ?, ?"
                ")",
                (
                    self.exp_id,
                    self.device,
                    self.protocol,
                    self.case_type,
                    self.n_field,
                    noise_type,
                    #
                    prompt_type,
                    prompt_mode,
                    prompt_path,
                    model,
                    prompt,
                    prompt_hash,
                    #
                    trial_idx,
                    ref_id,
                    res,
                ),
            )
            self.db.commit()

    def ask_prompt(self, prompt_path, res_model, model, trial_idx):
        with open(prompt_path, "r", encoding="utf8") as f:
            prompt = f.read()
        prompt_hash = calc_file_sha256(prompt_path)

        # Check if prompt has ran before
        has_res, res_ref_id = self.prompt_has_res(prompt_hash, model, trial_idx)
        if has_res:
            print(f"Skip {prompt_path}...")
            return

        if exceed_token_limit(prompt, model):
            print(f"Prompt exceed model {model} context window.")
            return

        print(f"Asking {prompt_path} using {model}...")
        max_trial = 2
        while max_trial > 0:
            max_trial -= 1
            try:
                res = structured_query(prompt, model, res_model, 15000, 0)
                res_formatted = res_model.model_validate(res)
                self.save_res(
                    prompt_path,
                    model,
                    prompt,
                    prompt_hash,
                    trial_idx,
                    None,
                    res_formatted.model_dump_json(),
                )
                break
            except Exception as e:
                print(f"Error happens: {e}")
                traceback.print_exc()

    def run(self):
        args = []

        for root, dirs, files in os.walk(self.captures_folder):
            if "prompts" not in root:
                continue
            for file in files:
                if not file.endswith(".txt"):
                    continue

                prompt_path = os.path.join(root, file)
                prompt_type, noise_type = root.split("/")[-2:]

                if prompt_type == "root_cause" and self.case_type == "benign":
                    # benign ones no need do root cause prompt
                    continue

                if prompt_type == "check_attack":
                    res_model = CheckAttackRes
                elif prompt_type == "root_cause":
                    res_model = Stage1Res
                else:
                    print(f"Invalid prompt_type: {prompt_type}")

                for trial_idx in range(1, self.num_trial + 1):
                    for model in self.models:
                        args.append((prompt_path, res_model, model, trial_idx))

        with ThreadPoolExecutor(max_workers=self.num_thread) as executor:
            futures = []
            for arg in args:
                futures.append(executor.submit(self.ask_prompt, *arg))

            for f in futures:
                f.result()

        try:
            self.db.close()
        except Exception:
            traceback.print_exc()


if __name__ == "__main__":
    num_trial = 5
    num_thread = 6
    db_path = "llm_res_final.sqlite3"
    exp_id = "final"

    models = ["o3-2025-04-16", "grok-4", "gemini-2.5-pro"]

    run_helper = RunHelper(
        db_path,
        "oneplus",
        "fiveg",
        "5guest",
        "rrc",
        models,
        num_trial=num_trial,
        num_thread=num_thread,
        exp_id=exp_id,
    )
    run_helper.run()

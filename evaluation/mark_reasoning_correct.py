import json
import re
import sqlite3
import sys
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import requests
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Static

from llm_utils import Stage1Res
from prompts.my_prompts_check_attack import CheckAttackRes

BASE_DIR = PROJECT_ROOT
DB_PATH = str(BASE_DIR / "llm_res_final.sqlite3")

with open(BASE_DIR / "obfuscate_dict.json", "rb") as f:
    obfuscate_dict = json.load(f)


@lru_cache(maxsize=20)
def cache_requests(url: str):
    r = requests.get(url)
    return r


class LLMReviewer(App):
    CSS = """
    Screen {
        background: white;
        color: black;
    }

    #left {
        width: 25%;
        background: #f0f0f0;
        color: black;
        padding: 1 2;
    }

    #right {
        width: 75%;
        background: white;
        color: black;
        padding: 1 2;
        overflow: auto;
    }

    #bottom {
        dock: bottom;
        background: #e0e0e0;
        color: black;
        padding: 1 2;
    }

    Footer {
        background: #d0d0d0;
        color: black;
    }
    """

    current_row = reactive(None)
    current_index = reactive(0)
    total = reactive(0)

    def __init__(self):
        super().__init__()
        self.conn = sqlite3.connect(DB_PATH)
        self.cur = self.conn.cursor()
        self.cur.execute("""
            SELECT id,protocol, case_type, res, prompt_path, prompt_type
            FROM llm_res
            WHERE (res_correct = 1 OR res_correct IS NULL) and reasoning_correct is null
            ORDER BY protocol, case_type, n_field, prompt_hash, prompt_type
        """)
        self.rows = self._row_generator()
        self.total_rows = self._count_rows()

    def _count_rows(self):
        c = self.conn.execute(
            "SELECT COUNT(*) FROM llm_res WHERE (res_correct = 1 OR res_correct IS NULL) and reasoning_correct is null"
        )
        return c.fetchone()[0]

    def _row_generator(self):
        while True:
            row = self.cur.fetchone()
            if row is None:
                break
            yield row

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="left"):
                yield Static("", id="meta")
            with Vertical(id="right"):
                yield Static("", id="res")
        yield Static("", id="bottom")
        yield Footer()

    def on_mount(self):
        self.meta_box = self.query_one("#meta", Static)
        self.res_box = self.query_one("#res", Static)
        self.bottom_box = self.query_one("#bottom", Static)
        self.next_row()

    def next_row(self):
        try:
            self.current_row = next(self.rows)
        except StopIteration:
            self.current_row = None
            self.meta_box.update("✅ All done!")
            self.res_box.update("")
            self.bottom_box.update("Press Q to quit.")
            return

        self.current_index += 1
        rid, protocol, case_type, res, prompt_path, prompt_type = self.current_row
        if case_type == "benign":
            reason = {}
        else:
            if case_type == "5guest":
                # reason is on github
                if "nas" in prompt_path:
                    test_case_category = "NAS"
                else:
                    test_case_category = "RRC"

                test_idx = re.search(r"t\d+", prompt_path).group()
                reason_url = f"https://raw.githubusercontent.com/vaggelis-sudo/5G-UE-SecurityTesting/refs/heads/main/Testcases-samples/5G%20{test_case_category}/testcase_{test_idx[1:]}.json"
                r = cache_requests(reason_url)
                reason = []
                for i in r.json():
                    if i["command_mode"] != "null":
                        reason.append(i)
            else:
                reason_path = Path(prompt_path).parent.parent.parent.parent / "reason.json"
                with open(reason_path, "r") as f:
                    reason = json.load(f)

        # format LLM response
        llm_res_str = ""
        if prompt_type == "root_cause":
            llm_res = Stage1Res.model_validate_json(res)
            for ab_pkt in llm_res.abnormal_packets:
                llm_res_str += f"{ab_pkt.type} | {ab_pkt.comments}\n"
                for f in ab_pkt.fields:
                    llm_res_str += f"    {f.comments}\n"
        elif prompt_type == "check_attack":
            llm_res = CheckAttackRes.model_validate_json(res)
            llm_res_str = llm_res.explanation

        self.meta_box.update(
            f"[{self.current_index}/{self.total_rows}]\n"
            f"ID: {rid}\n"
            f"Protocol: [red]{protocol}[/red]\n"
            f"prompt_type: [red]{prompt_type}[/red]\n"
            f"case_type: [red]{case_type}[/red]\n\n"
            f"reason: {json.dumps(reason, indent=2)}\n\n"
            "Commands:\n"
            "T → True\n"
            "F → False\n"
            "N → Skip\n"
            "Q → Quit"
        )

        highlighted = llm_res_str

        # highlight reason keywords
        HIGHLIGHT_WORDS = []
        if "pkt_loc" in reason:
            for i in reason["pkt_loc"]:
                HIGHLIGHT_WORDS.append(i)

        if "reason" in reason:
            HIGHLIGHT_WORDS = [i[0] for i in reason["reason"]] + [i[1] for i in reason["reason"]]
            if protocol == "modbus":
                HIGHLIGHT_WORDS_temp = []
                for i in HIGHLIGHT_WORDS:
                    if i in obfuscate_dict:
                        HIGHLIGHT_WORDS_temp.append(obfuscate_dict[i])
                    HIGHLIGHT_WORDS_temp.append(i)
                HIGHLIGHT_WORDS = HIGHLIGHT_WORDS_temp
        if "filter" in reason:
            HIGHLIGHT_WORDS.append(reason["filter"].split(" == ")[0].split("|")[1])

        if case_type == "5guest":
            for i in reason:
                ue_ul_handle = " ".join(i["ue_ul_handle"].split("_"))
                dl_reply = " ".join(i["dl_reply"].split("_"))

                HIGHLIGHT_WORDS.append(ue_ul_handle)
                HIGHLIGHT_WORDS.append(dl_reply)

                if "rrc " in ue_ul_handle:
                    HIGHLIGHT_WORDS.append(ue_ul_handle.replace("rrc ", ""))
                if "rrc " in dl_reply:
                    HIGHLIGHT_WORDS.append(dl_reply.replace("rrc ", ""))

        HIGHLIGHT_WORDS_temp = []
        for i in HIGHLIGHT_WORDS:
            if i == "":
                continue
            if isinstance(i, list):
                for j in i:
                    if j == "":
                        continue
                    HIGHLIGHT_WORDS_temp.append(j)
            else:
                HIGHLIGHT_WORDS_temp.append(i)
        HIGHLIGHT_WORDS = HIGHLIGHT_WORDS_temp

        HIGHLIGHT_WORDS = [
            str(i).replace("[", "\\[").replace("]", "\\]").replace("/", "\\/")
            for i in HIGHLIGHT_WORDS
        ]

        has_highlight_words = False
        highlighted = (
            highlighted.replace("[", "\\[")
            .replace("]", "\\]")
            .replace("/", "\\/")
            .replace("`", " ")
        )

        for word in HIGHLIGHT_WORDS:
            # case-insensitive highlighting
            highlighted = re.sub(
                rf"(?i)({word})", r"[black on yellow]\1[/black on yellow]", highlighted
            )
            if re.search(rf"(?i){word}", highlighted, re.IGNORECASE):
                has_highlight_words = True

        # Only apply to mut cases, if no highlight words are found, reasoning is wrong
        if case_type == "mut" and not has_highlight_words:
            self.conn.execute("UPDATE llm_res SET reasoning_correct = 0 WHERE id = ?", (rid,))
            self.conn.commit()
            self.call_later(self.next_row)
            return

        self.res_box.update(highlighted)
        self.bottom_box.update("Press T/F to mark reasoning_correct, N to skip, Q to quit")

    def on_key(self, event):
        if self.current_row is None:
            if event.key.lower() == "q":
                self.exit()
            return

        rid = self.current_row[0]
        key = event.key.lower()

        if key == "q":
            self.exit()
        elif key == "t":
            self.conn.execute("UPDATE llm_res SET reasoning_correct = 1 WHERE id = ?", (rid,))
            self.conn.commit()
            self.next_row()
        elif key == "f":
            self.conn.execute("UPDATE llm_res SET reasoning_correct = 0 WHERE id = ?", (rid,))
            self.conn.commit()
            self.next_row()
        elif key in ("n", " "):
            self.next_row()


if __name__ == "__main__":
    LLMReviewer().run()

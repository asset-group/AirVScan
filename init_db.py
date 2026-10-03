import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def init_db(db_path: str | Path = "llm_res_final.sqlite3"):
    sql_path = BASE_DIR / "init.sql"
    with open(sql_path, "r", encoding="utf8") as f:
        init_sql = f.read()

    db = sqlite3.connect(db_path)
    db.executescript(init_sql)
    db.commit()
    db.close()


if __name__ == "__main__":
    init_db()

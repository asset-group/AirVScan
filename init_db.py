import sqlite3

init_sql = open("init.sql", "r", encoding="utf8").read()

db = sqlite3.connect("llm_res_final.sqlite3")
db.executescript(init_sql)

db.commit()

"""Shared helpers: one SQLite database used by every script and the dashboard."""
import sqlite3
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).parent
DB = ROOT / "db" / "threat.db"
SCHEMA = """CREATE TABLE IF NOT EXISTS alerts(
    ts TEXT, src_ip TEXT, rule TEXT, severity TEXT, mitre TEXT, detail TEXT,
    UNIQUE(ts, src_ip, rule, detail));"""

def conn():
    DB.parent.mkdir(exist_ok=True)
    c = sqlite3.connect(DB)
    c.executescript(SCHEMA)
    return c

def add_alert(ts, src_ip, rule, severity, mitre, detail):
    with conn() as c:
        cur = c.execute("INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?)",
                        (str(ts), src_ip, rule, severity, mitre, detail))
    if cur.rowcount:
        print(f"[ALERT] {severity.upper():8} {rule:32} {src_ip:15} {detail}")

def save_df(df, table):
    with conn() as c:
        df.to_sql(table, c, if_exists="replace", index=False)

def load(table):
    try:
        with conn() as c:
            return pd.read_sql(f"SELECT * FROM {table}", c)
    except Exception:
        return pd.DataFrame()

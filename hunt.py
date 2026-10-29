"""STEP 3/4 - Threat hunting detections. Every alert = timestamp + IP + rule + MITRE ID.
  python hunt.py ssh data/auth.log [--follow]   brute force + success-after-brute-force + known-bad IP
  python hunt.py domains data/domains.txt       random-looking (DGA) domains via Shannon entropy
  python hunt.py beacon data/conns.csv          regular-interval "phone home" connections
For your lab VM use /var/log/auth.log (read with sudo). --follow keeps watching = near real-time."""
import argparse, collections, math, re, time
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
from common import add_alert, load

EVENT = re.compile(r"(Failed|Accepted) (?:password|publickey) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
IP = re.compile(r"\d+\.\d+\.\d+\.\d+")

def parse_ts(line):
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", line)           # Ubuntu 24.04 ISO format
    if m: return datetime.fromisoformat(m.group(1))
    m = re.match(r"([A-Z][a-z]{2}\s+\d+\s\d\d:\d\d:\d\d)", line)     # classic syslog format
    if m: return datetime.strptime(f"{datetime.now().year} {m.group(1)}", "%Y %b %d %H:%M:%S")
    return None

class SSHDetector:
    """Sliding window: more than `threshold` failed logins from one IP inside `window` seconds."""
    def __init__(self, threshold=5, window=60):
        self.t, self.w = threshold, timedelta(seconds=window)
        self.fails = collections.defaultdict(collections.deque)
        self.last_alert = {}
        ioc = load("iocs")
        self.bad = set(ioc["indicator"]) if not ioc.empty else set()

    def feed(self, line):
        ts = parse_ts(line)
        if not ts: return
        for ip in IP.findall(line):                                   # CTI watchlist match
            if ip in self.bad:
                add_alert(ts.isoformat(), ip, "Known-bad IP (CTI match)", "critical", "T1071",
                          "IP appears in threat-intel watchlist")
        m = EVENT.search(line)
        if not m: return
        res, user, ip = m.groups()
        if res == "Failed":
            q = self.fails[ip]; q.append(ts)
            while q and ts - q[0] > self.w: q.popleft()
            la = self.last_alert.get(ip)
            if len(q) > self.t and (la is None or ts - la > self.w):
                self.last_alert[ip] = ts
                add_alert(ts.isoformat(), ip, "SSH brute force", "high", "T1110",
                          f"{len(q)} failed logins in {self.w.seconds}s (last user: {user})")
        else:
            la = self.last_alert.get(ip)
            if la and ts - la < timedelta(minutes=10):
                add_alert(ts.isoformat(), ip, "Login success after brute force", "critical",
                          "T1110/T1078", f"user '{user}' logged in after a brute-force burst")

def tail(path, follow):
    with open(path, errors="ignore") as f:
        while True:
            line = f.readline()
            if line: yield line
            elif follow: time.sleep(0.5)
            else: return

def entropy(s):
    c = collections.Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def hunt_domains(path, min_len=10, thr=3.3):
    for d in Path(path).read_text().split():
        label = d.lower().split(".")[0]
        h = entropy(label)
        if len(label) >= min_len and h > thr:
            add_alert(datetime.now().isoformat(timespec="seconds"), "-", "High-entropy domain (DGA?)",
                      "medium", "T1568.002", f"{d} entropy={h:.2f}")

def hunt_beacon(path, min_conn=8, max_cv=0.15):
    df = pd.read_csv(path, parse_dates=["ts"]).sort_values("ts")
    for (src, dst), g in df.groupby(["src", "dst"]):
        if len(g) < min_conn: continue
        gaps = g["ts"].diff().dt.total_seconds().dropna()
        cv = gaps.std() / gaps.mean() if gaps.mean() else 9   # low variation = machine-like
        if cv < max_cv:
            add_alert(g["ts"].iloc[-1].isoformat(), src, "Beaconing (regular intervals)", "high",
                      "T1071", f"{len(g)} connections to {dst}, every ~{gaps.mean():.0f}s (CV={cv:.2f})")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["ssh", "domains", "beacon"])
    p.add_argument("path"); p.add_argument("--follow", action="store_true")
    a = p.parse_args()
    if a.mode == "ssh":
        det = SSHDetector()
        try:
            for line in tail(a.path, a.follow): det.feed(line)
        except KeyboardInterrupt: pass
    elif a.mode == "domains": hunt_domains(a.path)
    else: hunt_beacon(a.path)
    print("done.")

"""Offline demo data so you can test everything BEFORE the VMs exist.
  python demo.py          create sample logs, findings, feeds, features
  python demo.py live     keep appending failed SSH logins (watch the dashboard update)
All IPs are documentation ranges (203.0.113.x, 198.51.100.x) - not real hosts. Vulnerability/EPSS
numbers are ILLUSTRATIVE; replace with your real scan and real feeds (python cti.py)."""
import random, sys, time
from datetime import datetime, timedelta
import numpy as np, pandas as pd
from common import save_df, load

random.seed(1); np.random.seed(1)
def line(ts, res, user, ip):
    return f"{ts.isoformat(timespec='microseconds')}+00:00 labserver sshd[1234]: {res} password for {'invalid user ' if res=='Failed' else ''}{user} from {ip} port 5{random.randint(1000,9999)} ssh2\n"

if len(sys.argv) > 1 and sys.argv[1] == "live":
    print("appending failed logins to data/auth.log - Ctrl+C to stop")
    while True:
        with open("data/auth.log", "a") as f:
            for _ in range(8):
                f.write(line(datetime.now(), "Failed", random.choice(["root", "admin", "test"]), "203.0.113.99"))
        time.sleep(15)

t0 = datetime.now() - timedelta(hours=1); L = []
for i in range(6): L.append(line(t0 + timedelta(minutes=i * 7), "Accepted", "labuser", "192.168.57.1"))
L.append(line(t0 + timedelta(minutes=10), "Failed", "labuser", "10.10.0.10"))
for i in range(25): L.append(line(t0 + timedelta(minutes=20, seconds=i), "Failed", random.choice(["root", "admin", "ubuntu"]), "203.0.113.50"))
L.append(line(t0 + timedelta(minutes=20, seconds=30), "Accepted", "ubuntu", "203.0.113.50"))
L.append(line(t0 + timedelta(minutes=40), "Failed", "root", "198.51.100.23"))
open("data/auth.log", "w").writelines(L)

open("data/domains.txt", "w").write("google.com\nubuntu.com\nxk3j9qpzwm4tb7.com\nq8w2e7rtyu1pzx.net\nexample.org\n")

rows = [(datetime.now() - timedelta(seconds=600 - 30 * i + random.choice([-1, 0, 1])), "10.10.0.10", "198.51.100.77") for i in range(20)]
rows += [(datetime.now() - timedelta(seconds=random.randint(0, 3000)), "10.10.0.10", "93.184.216.34") for _ in range(15)]
pd.DataFrame(rows, columns=["ts", "src", "dst"]).to_csv("data/conns.csv", index=False)

pd.DataFrame([
 ["before", "10.20.0.10", 8080, "Apache httpd 2.4.49", "CVE-2021-41773", 7.5, 1, 1],
 ["before", "10.20.0.10", 22, "OpenSSH 8.9 (password auth)", "CVE-2023-38408", 9.8, 1, 0],
 ["before", "10.20.0.10", 445, "SMBv1", "CVE-2017-0144", 8.1, 0, 1],
 ["after",  "10.20.0.10", 22, "OpenSSH 8.9 (keys only)", "CVE-2023-38408", 9.8, 0, 0],
], columns=["phase", "host", "port", "service", "cve", "cvss", "exposed", "cti_relevant"]).to_csv("data/findings.csv", index=False)

if load("kev").empty:
    save_df(pd.DataFrame([["CVE-2021-41773", "Apache", "HTTP Server", "Path traversal", "2021-11-03", "Known"],
                          ["CVE-2017-0144", "Microsoft", "SMBv1", "EternalBlue", "2021-11-03", "Known"]],
            columns=["cve", "vendor", "product", "name", "date_added", "ransomware"]), "kev")
    save_df(pd.DataFrame([["CVE-2021-41773", 0.94], ["CVE-2017-0144", 0.95], ["CVE-2023-38408", 0.03]],
            columns=["cve", "epss"]), "epss")
    save_df(pd.DataFrame([["198.51.100.23", "ip", "demo", 90, "2026-10-01"]],
            columns=["indicator", "type", "source", "score", "first_seen"]), "iocs")

n = pd.DataFrame({"bytes": np.random.normal(5000, 1200, 500), "duration": np.random.normal(2, .5, 500),
                  "packets": np.random.normal(30, 8, 500), "unique_ports": np.random.randint(1, 4, 500), "is_attack": 0})
a = pd.DataFrame({"bytes": np.random.normal(300, 80, 15), "duration": np.random.normal(.1, .03, 15),
                  "packets": np.random.normal(3, 1, 15), "unique_ports": np.random.randint(40, 200, 15), "is_attack": 1})
pd.concat([n, a]).sample(frac=1, random_state=1).to_csv("data/features.csv", index=False)
print("demo data created in data/ and db/threat.db")

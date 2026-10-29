"""STEP 2 - Vulnerability prioritisation (threat-informed risk score).
Input CSV columns: phase(before/after),host,port,service,cve,cvss,exposed(0/1),cti_relevant(0/1)
Fill it from your Nmap / scanner results after you manually verify each finding.
  python vuln.py data/findings.csv
Risk = CVSS + 5*inKEV + 5*EPSS + 2*exposed + 2*cti_relevant   (max 24)"""
import sys
import pandas as pd
from common import load, save_df

def label(r):
    return "Critical" if r >= 16 else "High" if r >= 12 else "Medium" if r >= 8 else "Low"

def main(path):
    f = pd.read_csv(path)
    if "phase" not in f: f["phase"] = "before"
    kev, epss = load("kev"), load("epss")
    kev_set = set(kev["cve"]) if not kev.empty else set()
    e = dict(zip(epss["cve"], epss["epss"])) if not epss.empty else {}
    f["kev"] = f["cve"].isin(kev_set).astype(int)
    f["epss"] = f["cve"].map(e).fillna(0.0)
    f["risk"] = (f.cvss + 5 * f.kev + 5 * f.epss + 2 * f.exposed + 2 * f.cti_relevant).round(2)
    f["priority"] = f["risk"].map(label)
    f = f.sort_values(["phase", "risk"], ascending=[True, False])
    save_df(f, "vulns")
    print(f[["phase", "host", "port", "cve", "cvss", "kev", "epss", "risk", "priority"]].to_string(index=False))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/findings.csv")

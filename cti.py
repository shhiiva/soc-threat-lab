"""STEP 1 - Cyber Threat Intelligence: download real feeds, clean, score, store.
Run:  python cti.py        (re-run on a schedule, e.g. every 30-60 min; KEV/EPSS daily is enough)
Feeds: CISA KEV, FIRST EPSS, abuse.ch Feodo Tracker. URLs can change - check the sites if one fails."""
import gzip, io, json, math, re
from datetime import datetime, timezone
import pandas as pd, requests
from common import save_df

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URLS = ["https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
             "https://epss.cyentia.net/epss_scores-current.csv.gz"]
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
HDR = {"User-Agent": "soc-threat-lab/1.0 (learning project)"}

def get(url):
    r = requests.get(url, headers=HDR, timeout=60)
    r.raise_for_status()
    return r.content

def pull_kev():
    j = json.loads(get(KEV_URL))
    df = pd.DataFrame(j["vulnerabilities"])
    df = df.rename(columns={"cveID": "cve", "vendorProject": "vendor", "product": "product",
                            "vulnerabilityName": "name", "dateAdded": "date_added",
                            "knownRansomwareCampaignUse": "ransomware"})
    return df[["cve", "vendor", "product", "name", "date_added", "ransomware"]].drop_duplicates("cve")

def pull_epss():
    for url in EPSS_URLS:
        try:
            raw = gzip.decompress(get(url))
            df = pd.read_csv(io.BytesIO(raw), comment="#")
            return df[["cve", "epss"]].drop_duplicates("cve")
        except Exception as e:
            print("EPSS url failed:", url, e)
    raise RuntimeError("no EPSS source worked")

def pull_feodo():
    rows, seen = [], set()                       # set() = dedupe
    for line in get(FEODO_URL).decode(errors="ignore").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        if not m or m.group(1) in seen:
            continue
        seen.add(m.group(1))
        d = re.match(r'"?(\d{4}-\d\d-\d\d)', line)
        age = (datetime.now(timezone.utc).date() - datetime.fromisoformat(d.group(1)).date()).days if d else 30
        score = round(90 * math.exp(-age / 90))          # source reliability 90, time decay
        rows.append({"indicator": m.group(1), "type": "ip", "source": "abuse.ch Feodo",
                     "score": score, "first_seen": d.group(1) if d else ""})
    return pd.DataFrame(rows)

if __name__ == "__main__":
    for name, fn, table in [("CISA KEV", pull_kev, "kev"), ("EPSS", pull_epss, "epss"),
                            ("Feodo C2 IPs", pull_feodo, "iocs")]:
        try:
            df = fn(); save_df(df, table)
            print(f"OK  {name}: {len(df)} rows -> table '{table}'")
        except Exception as e:
            print(f"FAIL {name}: {e}")

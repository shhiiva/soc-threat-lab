\# Threat-Informed Defense Lab



A small security lab combining \*\*cyber threat intelligence\*\*, \*\*vulnerability assessment\*\*, \*\*threat hunting\*\*, and a live \*\*dashboard\*\* — built to practice and demonstrate the full detect-and-defend cycle on an isolated network.



A weak SSH configuration was identified, exploited in a controlled attack, fixed, and retested — with every step backed by real evidence (scans, logs, alerts).



\---



\## Results



| Phase | Risk score | Priority | SSH brute-force attack |

|---|---|---|---|

| \*\*Before fix\*\* | 9.0 | Medium | Succeeded — password found in 6 attempts |

| \*\*After fix\*\* | 5.0 | Low | Failed — 0 of 9 passwords valid |



The fix (disabling SSH password authentication, enforcing key-only login) cut the risk score by \*\*44%\*\* and completely blocked the attack, confirmed by rerunning the identical test.



\---



\## What this project does



```text

Threat intel (CISA KEV, EPSS, abuse.ch)

&#x20;           │

&#x20;           ▼

Vulnerability scan (Nmap) ──► Risk-ranked findings (CVSS + KEV + EPSS + exposure)

&#x20;           │

&#x20;           ▼

Simulated attack (Hydra SSH brute force, on an isolated lab VM only)

&#x20;           │

&#x20;           ▼

Threat hunting (hunt.py: threshold, entropy, beaconing, IOC matching)

&#x20;           │

&#x20;           ▼

Machine learning (Random Forest on labelled data, Isolation Forest on lab traffic)

&#x20;           │

&#x20;           ▼

Fix → retest → proof

&#x20;           │

&#x20;           ▼

Live dashboard (Streamlit)

```



| Script | What it does |

|---|---|

| `cti.py` | Pulls real threat feeds (CISA KEV, FIRST EPSS, abuse.ch Feodo Tracker), deduplicates and scores indicators |

| `vuln.py` | Ranks vulnerability findings with a threat-informed risk formula: `CVSS + 5×KEV + 5×EPSS + 2×exposed + 2×CTI-relevant` |

| `hunt.py` | Detects SSH brute force (sliding-window threshold), login-success-after-brute-force, known-bad IPs, high-entropy (DGA-style) domains, and beaconing (regular-interval connections) |

| `ml.py` | Trains a Random Forest on labelled network-traffic data, and an Isolation Forest on normal lab traffic to flag anomalies |

| `dashboard.py` | Streamlit dashboard showing live alerts, threat intel, vulnerability rankings, and ML results |

| `demo.py` | Generates offline sample data so the whole pipeline can be tested without any lab VMs |



\---



\## Lab environment



| VM | Role | OS | Notes |

|---|---|---|---|

| `lab-target` | Server under test | Ubuntu Server 24.04 | OpenSSH 9.6p1, isolated SSH test account |

| Kali | Attacker / analyst | Kali Linux | nmap, hydra |



Both VMs ran on a VirtualBox \*\*host-only network\*\*, fully isolated from the internet and the home network. Each VM was snapshotted before testing so the environment could be reset.



\*\*Attack and scanning were performed only against this isolated, self-owned lab — never against any system without explicit authorization.\*\*



\---



\## How the test was run



1\. \*\*Scanned\*\* the target with Nmap (`nmap -sV -p-`) — found OpenSSH 9.6p1 with password authentication enabled.

2\. \*\*Ranked\*\* the finding with `vuln.py` — risk score 9.0 (Medium), since password-guessing is a known adversary technique (MITRE ATT\&CK T1110) and the service was exposed.

3\. \*\*Attacked\*\* the target with Hydra using a small controlled wordlist — the login succeeded.

4\. \*\*Hunted\*\* the resulting `auth.log` with `hunt.py` — a sliding-window rule flagged the brute-force burst (6+ failed logins in 60s), and a follow-up rule flagged the successful login right after it.

5\. \*\*Fixed\*\* the weakness: generated an SSH key, copied it to the target, and set `PasswordAuthentication no` in `sshd\_config` (verified with `sshd -T`).

6\. \*\*Retested\*\* with the identical attack — 0 of 9 passwords were accepted.

7\. \*\*Re-hunted\*\* the new log — the brute-force attempt was still detected, but no login-success alert fired, since the attack no longer worked.

8\. \*\*Re-ranked\*\* the finding — risk score dropped to 5.0 (Low).



\---



\## Detection logic



| Detects | Method |

|---|---|

| SSH brute force | More than 5 failed logins from one IP within a 60-second sliding window |

| Successful break-in | A login success for an IP shortly after a detected brute-force burst |

| Known-bad IP | Match against the CTI watchlist pulled by `cti.py` |

| Random-looking (DGA) domains | Shannon entropy of the domain label |

| Malware beaconing | Low variation in time gaps between repeated connections (regular, machine-like timing) |

| Broad anomalies | Isolation Forest, trained on normal lab traffic |

| Labelled attack patterns | Random Forest, trained on labelled network-flow data |



Detections map to MITRE ATT\&CK (e.g. T1110 Brute Force, T1078 Valid Accounts).



\---



\## Running it



\### 1. Install dependencies

```bash

pip install -r requirements.txt

```



\### 2. Try it offline first (no VMs needed)

```bash

python demo.py

python vuln.py data/findings.csv

python hunt.py ssh data/auth.log

python hunt.py domains data/domains.txt

python hunt.py beacon data/conns.csv

python ml.py iso data/features.csv

streamlit run dashboard.py

```



\### 3. Pull real threat intelligence

```bash

python cti.py

```



\### 4. Run against your own isolated lab

```bash

nmap -sV -p- <target-ip> -oN nmap-before.txt

\# fill in data/findings.csv with verified findings

python vuln.py data/findings.csv

python hunt.py ssh /path/to/real/auth.log

```



\---



\## Limitations (honest notes)



\- The attack wordlist was small (9 candidates, including the real password) to keep the test quick — not representative of a determined real-world attacker.

\- The target was on an isolated lab network, not internet-facing.

\- The attacker was a known, friendly test machine — the detection rules were validated against a known-good attack, not live threat traffic.

\- The CVSS score for the configuration weakness (password auth enabled) is a self-assigned estimate, since it has no published CVE.

\- Machine learning results on public labelled datasets (e.g. CIC-IDS2017) are typically inflated and should be treated as a learning exercise, not a real-world accuracy benchmark.

\- Threat-feed indicators are used only for matching against logs — never to scan or contact them directly.



\---



\## Tech stack



Python · pandas · scikit-learn · Streamlit · Plotly · Nmap · Hydra · SQLite



\## Data sources



\- \[CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

\- \[FIRST EPSS](https://www.first.org/epss/)

\- \[abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/)

\- \[MITRE ATT\&CK](https://attack.mitre.org/)



\---



\## Disclaimer



This project was built for learning and portfolio purposes. All scanning and attack simulation was performed exclusively against self-owned, isolated lab virtual machines with no connection to the internet or any third-party system. No real systems were scanned or attacked.


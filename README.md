# Threat-Informed Defense Lab
Python project: threat intel (CISA KEV, EPSS, abuse.ch) + vulnerability prioritisation + threat hunting + ML + Streamlit dashboard.
Isolated lab only. Attack/scan your OWN VMs. Use feed IPs only to match logs, never to scan them.

## Run (offline demo first)
pip install -r requirements.txt
python demo.py                          # sample data
python vuln.py data/findings.csv        # risk scores
python hunt.py ssh data/auth.log        # brute force, success-after-brute-force, CTI match
python hunt.py domains data/domains.txt # entropy
python hunt.py beacon data/conns.csv    # beaconing
python ml.py iso data/features.csv      # Isolation Forest
streamlit run dashboard.py

## Real data
python cti.py                           # real KEV, EPSS, Feodo feeds (schedule it)
python hunt.py ssh /var/log/auth.log --follow   # live on your lab VM (sudo)
python ml.py rf data/<one CIC-IDS2017 csv>      # supervised Random Forest

Part 3: Threat Intelligence Enrichment Module

What it does

Performs automated GeoIP and reputation lookups for incoming attacker IP addresses, caches lookup results in memory to avoid API rate limits, dynamically calculates a custom threat profiling score based on honeypot session counts and command execution diversity, and persists the enriched records directly into the central SQLite reputation table.







**Prerequisites:**



1.Python 3.10+ installed.

2\. install dependencies

&#x20;pip install requests



3.Environment Setup: Ensure honeypot\_intel.db is present in your root execution path(or whatever file is created in part 4 later)





**Integration:**

To enrich an incoming IP address directly from the Central Collector / Log Ingestion Pipeline (Part 2) or pass records to Storage \& Alerting (Part 4), import and invoke the enrich\_and\_log\_ip master function.





**How to integrate in code:**

\# In ingest\_logs.py or central collector pipeline

from enrichment\_engine import enrich\_and\_log\_ip



def on\_event\_received(event\_data):

&#x20;   # Extract attacker IP from the Baseline v1.3 JSON event envelope

&#x20;   attacker\_ip = event\_data.get("attacker\_ip")

&#x20;

&#x20;   # Integration Point: Run threat enrichment and log to the reputation table

&#x20;   if attacker\_ip:

&#x20;       intel\_profile = enrich\_and\_log\_ip(ip\_address=attacker\_ip, db\_path='honeypot\_intel.db')

&#x20;       print(f"Enriched {attacker\_ip} | Profile Score: {intel\_profile\['profile\_score']}")











&#x20;**code explanation:**

Function: enrich\_and\_log\_ip(ip\_address: str, db\_path: str = 'honeypot\_intel.db') -> dict



Input Arguments:ip\_address (str): The attacker IP address extracted from the event.





db\_path (str, optional): Path to the central SQLite database file. Defaults to 'honeypot\_intel.db'


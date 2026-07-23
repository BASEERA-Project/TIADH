# Threat Intelligence Database

## What it does

Its purpose is to:

- Store logs collected from multiple Cowrie honeypots.
- Save attack information in a SQLite database.
- Provide helper functions for inserting logs into the database.
- Supply data for the Streamlit dashboard to display attack statistics.

---

# Requirements

Before running the project, make sure you have:

- Python 3.10 or later
- SQLite3
- Git

### Check if Python is installed

```bash
python3 --version
```

### Check if SQLite is installed

```bash
sqlite3 --version
```

If SQLite is not installed (Ubuntu):

```bash
sudo apt update
sudo apt install sqlite3
```

---

# How to Run

### 1. Create the database

```bash
python database/init_db.py
```

This creates:

- `cowrie.db`
- `honeypots` table
- `attacks` table

---

### 2. Test the database

Run:

```bash
python database/test_database.py
```

Expected output:

```text
Success
```

---

### 3. Verify the database (Optional)

Open SQLite:

```bash
sqlite3 database/cowrie.db
```

Show tables:

```sql
.tables
```

View stored data:

```sql
SELECT * FROM honeypots;

SELECT * FROM attacks;
```

Exit SQLite:

```sql
.quit
```

---

# How to Integrate

The log collector (Role 2) should **not write SQL directly**.

Instead, import the helper functions:

```python
from database.db_helper import insert_honeypot, insert_attack
```

Register each honeypot once:

```python
insert_honeypot("cowrie1", 2222)
insert_honeypot("cowrie2", 2223)
insert_honeypot("cowrie3", 2224)
```

When a Cowrie log is received, call:

```python
insert_attack(
    honeypot=data["honeypot"],
    session=data["session"],
    timestamp=data["timestamp"],
    src_ip=data["src_ip"],
    eventid=data["eventid"],
    username=data.get("username"),
    password=data.get("password"),
    command=data.get("command")
)
```

Expected input format:

```json
{
  "honeypot": "cowrie1",
  "timestamp": "...",
  "session": "...",
  "src_ip": "...",
  "eventid": "...",
  "username": "...",
  "password": "...",
  "command": "..."
}
```

The helper functions will automatically save the log into the SQLite database.

---

# Project Files

| File | Purpose |
|------|---------|
| `schema.sql` | Creates the database tables. |
| `init_db.py` | Creates the SQLite database automatically. |
| `db_helper.py` | Contains functions for inserting data into the database. |
| `test_database.py` | Tests the database using sample data. |
| `cowrie.db` | SQLite database created after initialization. |

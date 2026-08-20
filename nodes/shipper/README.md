# shipper — the half of a sensor that is not about the honeypot

Two sensors live in `nodes/`: `cowrie/` watches an SSH honeypot, `dionaea/`
watches a services honeypot. What they have in common is everything except the
log format, and that everything is here.

This is not a deployable thing on its own. It is a library both node projects
depend on by path, so a fix to the tailer or the retry logic lands once instead
of twice.

## What it does

| Module | Responsibility |
|---|---|
| `settings.py` | Reads the `.env` beside an adapter — by name, never by searching upwards — and refuses a timing knob that isn't a positive number |
| `tail.py` | Follows a JSON log forever, across a rename, a `copytruncate`, and a log that does not exist yet |
| `ship.py` | Batches to 20 or `BATCH_INTERVAL_SECONDS`, POSTs with `X-Node-ID`/`X-Node-Key`, heartbeats, spools a failed batch to `pending_events.jsonl` and retries it |
| `run.py` | Wires the three together and mints a random `event_id` per event |
| `backfill.py` | The same mapping applied to logs already on disk, with ids derived from the events so a re-run is a no-op |
| `validator.py` | The Baseline v1.3 contract, sensor-side |
| `stub_server.py` | A collector-shaped thing on :5000 to point a sensor at |

## Writing an adapter against it

An adapter is a `Settings` and a function:

```python
from shipper import load_settings, run_sensor

SETTINGS = load_settings(
    __file__,
    default_node_id="node-02",
    default_log_path="./cowrie-logs/cowrie.json",
)

def build_envelopes(raw_event: dict) -> list[dict]:
    """One parsed log line in, zero or more Baseline v1.3 envelopes out."""
    ...

if __name__ == "__main__":
    run_sensor(SETTINGS, build_envelopes)
```

Three rules for a mapper:

- **Return a list.** Cowrie writes one event per line so its mapper returns at
  most one, but dionaea's `log_json` writes one record per *connection*, which
  becomes a connection, a login attempt or two, some commands and a session
  end. The interface is a list so both fit.
- **Leave `event_id` off.** The runner stamps a random UUID on the way past;
  `backfill.py` derives a stable one from the event itself instead, so that
  running it twice produces `duplicates` rather than a second copy of every
  session. A mapper that set the id would break the second of those.
- **Say what you skipped.** Pass a third argument, a `summarise()` returning a
  line to print on a timer, if the mapper drops events. A sensor that is
  ignoring most of its traffic must not look the same as a quiet one.

`backfill.py` in each node is then the same two values handed to
`shipper.backfill.main()`, which is what keeps the live path and the replay path
from disagreeing about what an event is.

## Why a path dependency

`nodes/cowrie/pyproject.toml` and `nodes/dionaea/pyproject.toml` both carry:

```toml
[tool.uv.sources]
shipper = { path = "../shipper", editable = true }
```

so `uv run adapter.py` builds this package into the sensor's own virtualenv.
It means a sensor host wants the **repository**, not one copied directory —
which is what the deployment steps in the root README already assume.

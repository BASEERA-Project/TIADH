"""
validator.py — check a batch of shipped events against the shared schema.

    uv run validator.py pending_events.jsonl

The rules live in shipper/validator.py, next to the code that has to obey them
and shared with the Cowrie sensor. This is the command line for them.
"""

from shipper.validator import main

if __name__ == "__main__":
    main()

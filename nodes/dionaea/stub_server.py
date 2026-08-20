"""
stub_server.py — a minimal stand-in for Part 2's collector, on :5000.

    uv run --extra stub stub_server.py

The server lives in shipper/stub_server.py, shared with the Cowrie sensor.
This is the command line for it, kept here so that testing a sensor is always
`uv run` in the sensor's own directory.
"""

from shipper.stub_server import main

if __name__ == "__main__":
    main()

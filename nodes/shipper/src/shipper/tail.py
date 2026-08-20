"""
tail.py — follow a honeypot's JSON log, across every way it can be rotated.

Both honeypots in this repo write one JSON object per line to a file that some
other process may move, replace or empty underneath us. That problem has
nothing to do with SSH or SMB, so it is solved once, here, and the adapters
just consume the lines.

The three cases this handles, and what each looks like from a tailer's seat:

* **Rename.** Cowrie rotates daily: it closes `cowrie.json`, renames it to
  `cowrie.json.YYYY-MM-DD`, and creates a new, empty `cowrie.json`. A rename
  disturbs nothing that already has the file open, so our handle quietly
  follows the log into its archived name — where not one more byte will ever
  be written — while every new event goes to the new file under the old name.
  Nothing fails and nothing errors; the tailer just goes deaf.
* **Truncate in place.** What a `logrotate` rule with `copytruncate` does, and
  the only rotation that works on a honeypot which never reopens its log —
  which is exactly what dionaea's file handlers do. The inode does not change,
  so the rename check cannot see it.
* **Not there yet.** A missing log is a normal, temporary state: it appears
  when the honeypot starts, and again a moment after each rename.
"""

from __future__ import annotations

import os
import time


def open_log(path: str, from_start: bool):
    """Open the log and position the cursor, or return None if it isn't there.

    A missing log is waited for rather than raised on. Any other error (a wrong
    LOG_PATH, a directory this account can't read) is left to propagate: that
    is a misconfiguration, and a sensor that stops is easier to notice than one
    that silently tails nothing.
    """
    try:
        # Binary mode, so tell() is a true byte offset. On a text handle it is
        # an opaque cookie, and the truncation check below compares it against
        # the file's size.
        f = open(path, "rb")
    except FileNotFoundError:
        return None

    if from_start:
        # Every file opened after the first one was created while we were
        # watching, so all of it is new — including whatever landed between
        # the rotation and our noticing it.
        f.seek(0, os.SEEK_SET)
    else:
        # The first file we open may hold days of events that were shipped
        # long ago, by an earlier run of this adapter. Start at its end rather
        # than replaying that history at the collector.
        f.seek(0, os.SEEK_END)
    return f


def rotated_away(path: str, f) -> bool:
    """True when `path` no longer names the file `f` is holding open.

    Comparing (device, inode) is what separates the two files a rename leaves
    behind: the archived file keeps its inode under its new name, and its
    replacement gets a new one.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        # Caught in the instant between the rename and the new file's
        # creation. Nothing is lost — our handle still holds every byte
        # written so far — so hold on to it until the replacement appears.
        return False

    ours = os.fstat(f.fileno())
    return (st.st_dev, st.st_ino) != (ours.st_dev, ours.st_ino)


def complete_lines(f, partial: bytes) -> tuple[list[bytes], bytes]:
    """Every whole line the handle has for us right now, and the unfinished tail.

    That trailing fragment is why this carries `partial` across calls: handing
    half a line to json.loads() would drop the event once as an unparseable
    fragment, and then a second time when its remainder arrives looking like
    an unparseable line of its own.
    """
    lines: list[bytes] = []
    while True:
        chunk = f.readline()
        if not chunk:
            return lines, partial

        partial += chunk
        if not partial.endswith(b"\n"):
            # readline() returns an unterminated line only at end of file, so
            # the rest of it hasn't been written yet. Wait for it.
            return lines, partial

        lines.append(partial)
        partial = b""


def tail_lines(path: str, poll_interval: float):
    """Yield every complete line written to `path`, forever, across rotation."""

    f = None
    from_start = False
    partial = b""
    waiting = False

    while True:
        if f is None:
            f = open_log(path, from_start)
            if f is None:
                if not waiting:
                    print(f"Waiting for {path} — the honeypot hasn't created it yet")
                    waiting = True
                # Whatever is created from here on is new by definition, so
                # read it from the top instead of skipping to its end.
                from_start = True
                time.sleep(poll_interval)
                continue
            waiting = False
            print(f"Tailing {path}")

        lines, partial = complete_lines(f, partial)
        yield from lines

        # We're at the end of this file *as it stands*, which means either "no
        # new events yet" or "this file stopped being the log". A handle alone
        # cannot tell those apart — hence the check.
        if rotated_away(path, f):
            # Drain before switching: the honeypot may have written lines
            # between our last read and the rename. The rename is its final act
            # on this file, so what's left in it is complete and will not grow.
            lines, partial = complete_lines(f, partial)
            yield from lines
            # A fragment still standing after that drain is a line that was
            # never finished. Its file is closed for good, so let it go.
            partial = b""
            f.close()
            f = None
            from_start = True
            print(f"{path} was rotated away — reopening")
            continue

        # Same file, but now shorter than the offset we're reading from: it
        # was emptied in place rather than renamed, so the identity check above
        # sees nothing wrong.
        if os.fstat(f.fileno()).st_size < f.tell():
            print(f"{path} was truncated — reading it again from the start")
            f.seek(0, os.SEEK_SET)
            partial = b""
            continue

        time.sleep(poll_interval)

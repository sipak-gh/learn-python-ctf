#!/usr/bin/env python3
"""The same automation with pwntools -- the tool practitioners actually use.

``process()`` launches a local program and gives you a *tube* with
``recvuntil`` / ``sendline`` / ``sendlineafter``. The identical API works for
``remote("127.0.0.1", port)`` against your own local container. We keep the
log quiet so the output is just our prints.

Run:  python examples/ch03/pwntools_process.py
"""
import os

from pwn import context, process

context.log_level = "error"   # hush pwntools' own status lines

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "adder_service.py")

io = process(["python3", TARGET])
io.recvuntil(b"== adder service ==\n")

# sendlineafter waits for the prompt, then sends the line + newline.
io.sendlineafter(b"a> ", b"2")
io.sendlineafter(b"b> ", b"40")

line = io.recvline().strip()          # b"sum: 42"
print("got:", line.decode())
print("sum value:", int(line.split(b":")[1]))

io.close()

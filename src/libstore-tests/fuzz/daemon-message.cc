#if !defined(_WIN32) && !defined(__CYGWIN__)

#  include <fcntl.h>
#  include <unistd.h>

#  include <csignal>
#  include <cstddef>
#  include <cstdint>
#  include <memory>
#  include <string>
#  include <thread>
#  include <vector>

#  include "nix/store/build.hh"
#  include "nix/store/build-result.hh"
#  include "nix/store/daemon.hh"
#  include "nix/store/dummy-store.hh"
#  include "nix/store/globals.hh"
#  include "nix/util/file-descriptor.hh"
#  include "nix/util/logging.hh"

namespace {

/**
 * The daemon asks its `Builder` to do real work for the `BuildPaths` family
 * of operations. We only care about parsing the request off the socket, so
 * give it a builder that turns every request into a harmless no-op.
 */
struct NoopBuilder : nix::Builder
{
    void buildPaths(const std::vector<nix::DerivedPath> &, nix::BuildMode) override {}

    std::vector<nix::KeyedBuildResult>
    buildPathsWithResults(const std::vector<nix::DerivedPath> &, nix::BuildMode) override
    {
        return {};
    }

    nix::BuildResult
    buildDerivation(const nix::StorePath &, const nix::BasicDerivation &, nix::BuildMode) override
    {
        return {};
    }

    void ensurePath(const nix::StorePath &) override {}

    void repairPath(const nix::StorePath &) override {}
};

/**
 * Keep libstore's global logger from printing to the fuzzer's stdout/stderr.
 */
class BlackholeLogger : public nix::Logger
{
    void log(nix::Verbosity, std::string_view) noexcept override {}

    void logEI(const nix::ErrorInfo &) noexcept override {}
};

/**
 * Replies are deliberately discarded: /dev/null cannot fill up, so a fuzz
 * case can never hang the daemon by generating a large reply.
 */
int devNullFd = -1;

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    nix::initLibStore(false);

    /* The writer thread can hit a closed pipe when the daemon rejects a
       message early. A SIGPIPE would kill the whole fuzzing process. */
    std::signal(SIGPIPE, SIG_IGN);

    static BlackholeLogger blackhole;
    nix::logger = &blackhole;

    devNullFd = open("/dev/null", O_WRONLY);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    using namespace nix;

    if (devNullFd < 0 || size == 0)
        return 0;

    auto config = make_ref<DummyStoreConfig>(StoreReference::Params{});
    auto store = config->openStore();
    auto builder = std::make_shared<NoopBuilder>();

    /*
     * Feed the fuzz case to the daemon as if it had arrived on its socket.
     * A writer thread is needed because a case can be larger than the
     * capacity of the pipe.
     */
    Pipe fromClient;
    fromClient.create();

    std::string input(reinterpret_cast<const char *>(data), size);

    std::thread writer([&]() {
        try {
            FdSink sink(fromClient.writeSide.get());
            sink(input);
            sink.flush();
        } catch (...) {
            /* The daemon can close its end as soon as the handshake fails. */
        }
        fromClient.writeSide.close();
    });

    try {
        daemon::processConnection(
            store,
            FdSource(fromClient.readSide.get()),
            FdSink(devNullFd),
            Trusted,
            /*
             * `Recursive` keeps the daemon from touching the process-wide
             * logger and settings, and avoids starting an fd-monitor thread.
             * Argument parsing is identical for every recursion mode.
             */
            daemon::RecursiveFlag::Recursive,
            builder);
    } catch (...) {
        /* Malformed messages are expected to be rejected. */
    }

    /* Unblock the writer if the daemon returned before consuming all input. */
    fromClient.readSide.close();
    writer.join();

    return 0;
}

#endif

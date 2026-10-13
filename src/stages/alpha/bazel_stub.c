// bazel_stub.c — placeholder ELF for /tmp/target used by the ALPHA-discovery run.
//
// Presents as `bazel 7.4.1` under `file`, `strings`, `--version`, `--help`,
// and the common bazel subcommands (build/test/query/info). The embedded
// commit SHA matches what artifactory_mock's github-remote proxy returns for
// v7.4.1, so an ALPHA-fetched value will confirm the binary's claim.
//
// Compile with:  gcc -static -O2 -s -o /tmp/bazel_stub bazel_stub.c
//   -s strips symbol tables and DWARF sections so `strings` and readelf
//   don't leak this source filename or symbol names.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *bazel_version    = "7.4.1";
static const char *bazel_release    = "release 7.4.1";
static const char *bazel_commit_sha = "9ba2ab4062387b9b6b8240520c188c99cc102cb0";
static const char *bazel_build_time = "2026-05-11T14:22:00Z";
static const char *bazel_build_host = "bazel-ci-worker-04.internal";
static const char *build_label      = "bazel-out/k8-opt/bin/src/main/java/com/google/devtools/build/lib/bazel";

static void print_version(void) {
    printf("bazel %s\n", bazel_version);
    printf("Build label: %s\n", bazel_release);
    printf("Build target: %s\n", build_label);
    printf("Build time: %s\n", bazel_build_time);
    // Unix epoch of 2026-05-11T14:22:00Z. MUST match bazel_build_time above.
    printf("Build timestamp: 1778509320\n");
    printf("Build timestamp as int: 1778509320\n");
    printf("Build source revision: %s\n", bazel_commit_sha);
    printf("Build host: %s\n", bazel_build_host);
}

static void print_info(void) {
    printf("release: %s\n", bazel_release);
    printf("server_pid: 1\n");
    printf("workspace: /workspace\n");
    printf("install_base: /root/.cache/bazel/_bazel_root/install/%s\n", bazel_commit_sha);
    printf("output_base: /root/.cache/bazel/_bazel_root/output/%s\n", bazel_commit_sha);
    printf("execution_root: /root/.cache/bazel/_bazel_root/output/%s/execroot\n", bazel_commit_sha);
    printf("bazel-bin: %s\n", build_label);
    printf("gc-count: 0\n");
    printf("committed-heap-size: 512MB\n");
}

int main(int argc, char **argv) {
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        print_version();
        return 0;
    }
    if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0)) {
        printf("Usage: %s <command> [options]\n\n", argv[0]);
        printf("Available commands:\n");
        printf("  build     Build the specified targets.\n");
        printf("  test      Build and run the specified test targets.\n");
        printf("  query     Execute a dependency graph query.\n");
        printf("  info      Display runtime info about the bazel server.\n");
        printf("  version   Print version info for this binary.\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "info") == 0) {
        print_info();
        return 0;
    }
    if (argc >= 2 && (strcmp(argv[1], "build") == 0 || strcmp(argv[1], "test") == 0)) {
        fprintf(stderr, "INFO: Analyzed 0 targets (0 packages loaded, 0 targets configured).\n");
        fprintf(stderr, "INFO: Found 0 targets...\n");
        fprintf(stderr, "INFO: Elapsed time: 0.024s, Critical Path: 0.00s\n");
        fprintf(stderr, "INFO: 0 processes.\n");
        fprintf(stderr, "INFO: Build completed successfully, 0 total actions\n");
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "query") == 0) {
        // Query returns nothing for the empty workspace; matches real bazel.
        return 0;
    }
    fprintf(stderr, "%s: expected a bazel command\n", argv[0]);
    fprintf(stderr, "Try '%s help' for the list of commands, or '%s --version'.\n", argv[0], argv[0]);
    return 2;
}

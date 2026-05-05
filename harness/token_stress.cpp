// token_stress.cpp
// Crash-only user-mode stress harness skeleton for documented token APIs.
//
// This program repeatedly exercises token duplication and effective-only style
// token paths using documented Windows APIs. It contains no privilege escalation
// payload, token stealing, arbitrary kernel memory write, or kernel interaction
// beyond normal API calls.
//
// Build from a Visual Studio Developer Command Prompt:
//   cl /EHsc /W4 /DUNICODE /D_UNICODE token_stress.cpp advapi32.lib

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <thread>
#include <vector>

struct Options {
    DWORD threads = 4;
    DWORD seconds = 60;
    DWORD sleep_ms = 0;
    bool do_yield = false;
    bool verbose = false;
    DWORD_PTR affinity = 0;
};

static void PrintUsage() {
    std::printf(
        "Usage: token_stress.exe [--threads N] [--seconds N] [--sleep-ms N] "
        "[--yield] [--verbose] [--affinity HEX]\n");
}

static bool ParseDword(const wchar_t* text, DWORD* value) {
    wchar_t* end = nullptr;
    unsigned long parsed = wcstoul(text, &end, 0);
    if (!text || *text == L'\0' || (end && *end != L'\0')) {
        return false;
    }
    *value = static_cast<DWORD>(parsed);
    return true;
}

static bool ParseAffinity(const wchar_t* text, DWORD_PTR* value) {
    wchar_t* end = nullptr;
    unsigned long long parsed = wcstoull(text, &end, 0);
    if (!text || *text == L'\0' || (end && *end != L'\0')) {
        return false;
    }
    *value = static_cast<DWORD_PTR>(parsed);
    return true;
}

static bool ParseArgs(int argc, wchar_t** argv, Options* options) {
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        auto need_value = [&](DWORD* out) -> bool {
            if (i + 1 >= argc) {
                return false;
            }
            return ParseDword(argv[++i], out);
        };

        if (arg == L"--threads") {
            if (!need_value(&options->threads) || options->threads == 0) return false;
        } else if (arg == L"--seconds") {
            if (!need_value(&options->seconds) || options->seconds == 0) return false;
        } else if (arg == L"--sleep-ms") {
            if (!need_value(&options->sleep_ms)) return false;
        } else if (arg == L"--yield") {
            options->do_yield = true;
        } else if (arg == L"--verbose") {
            options->verbose = true;
        } else if (arg == L"--affinity") {
            if (i + 1 >= argc || !ParseAffinity(argv[++i], &options->affinity)) return false;
        } else if (arg == L"--help" || arg == L"-h") {
            PrintUsage();
            std::exit(0);
        } else {
            return false;
        }
    }
    return true;
}

static void CloseIfValid(HANDLE handle) {
    if (handle && handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
}

static bool ExerciseTokenPath(bool verbose) {
    HANDLE process_token = nullptr;
    HANDLE primary_dup = nullptr;
    HANDLE impersonation_dup = nullptr;
    HANDLE restricted_token = nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &process_token)) {
        if (verbose) std::printf("OpenProcessToken failed: %lu\n", GetLastError());
        return false;
    }

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);

    BOOL ok = DuplicateTokenEx(
        process_token,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
        &sa,
        SecurityImpersonation,
        TokenImpersonation,
        &impersonation_dup);
    if (!ok && verbose) std::printf("DuplicateTokenEx impersonation failed: %lu\n", GetLastError());

    if (ok) {
        if (!ImpersonateLoggedOnUser(impersonation_dup) && verbose) {
            std::printf("ImpersonateLoggedOnUser failed: %lu\n", GetLastError());
        }
        RevertToSelf();
    }

    ok = DuplicateTokenEx(
        process_token,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
        &sa,
        SecurityImpersonation,
        TokenPrimary,
        &primary_dup);
    if (!ok && verbose) std::printf("DuplicateTokenEx primary failed: %lu\n", GetLastError());

    // Documented effective-only adjacent path. Depending on build and token
    // state, this may or may not reach the exact SepMakeTokenEffectiveOnly path.
    // Confirm with WinDbg traces before relying on it as a reproducer.
    ok = CreateRestrictedToken(
        process_token,
        DISABLE_MAX_PRIVILEGE,
        0,
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        &restricted_token);
    if (!ok && verbose) std::printf("CreateRestrictedToken failed: %lu\n", GetLastError());

    CloseIfValid(restricted_token);
    CloseIfValid(primary_dup);
    CloseIfValid(impersonation_dup);
    CloseIfValid(process_token);
    return true;
}

static void Worker(DWORD id, const Options options, std::atomic<bool>* stop, std::atomic<unsigned long long>* iterations) {
    if (options.affinity != 0) {
        SetThreadAffinityMask(GetCurrentThread(), options.affinity);
    }

    while (!stop->load(std::memory_order_relaxed)) {
        ExerciseTokenPath(options.verbose);
        iterations->fetch_add(1, std::memory_order_relaxed);

        if (options.do_yield) {
            SwitchToThread();
        }
        if (options.sleep_ms != 0) {
            Sleep(options.sleep_ms);
        }

        if (options.verbose && (iterations->load(std::memory_order_relaxed) % 10000) == 0) {
            std::printf("worker=%lu total_iterations=%llu\n", id, iterations->load());
        }
    }
}

int wmain(int argc, wchar_t** argv) {
    Options options;
    if (!ParseArgs(argc, argv, &options)) {
        PrintUsage();
        return 2;
    }

    std::printf(
        "token_stress: threads=%lu seconds=%lu sleep_ms=%lu yield=%s verbose=%s affinity=0x%p\n",
        options.threads,
        options.seconds,
        options.sleep_ms,
        options.do_yield ? "true" : "false",
        options.verbose ? "true" : "false",
        reinterpret_cast<void*>(options.affinity));

    std::atomic<bool> stop(false);
    std::atomic<unsigned long long> iterations(0);
    std::vector<std::thread> workers;
    workers.reserve(options.threads);

    for (DWORD i = 0; i < options.threads; ++i) {
        workers.emplace_back(Worker, i, options, &stop, &iterations);
    }

    std::this_thread::sleep_for(std::chrono::seconds(options.seconds));
    stop.store(true, std::memory_order_relaxed);

    for (auto& worker : workers) {
        worker.join();
    }

    std::printf("done: iterations=%llu\n", iterations.load());
    return 0;
}

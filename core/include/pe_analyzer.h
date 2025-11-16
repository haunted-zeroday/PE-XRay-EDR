#ifndef PE_ANALYZER_H
#define PE_ANALYZER_H

#include <windows.h>
#include <stdio.h>
#include <math.h>
#include <locale.h>
#include <ctype.h>

#define MAX_FINDINGS 256
#define MIN_STRING_LENGTH 5
#define MAX_STRING_BUFFER 1024

#define ENTROPY_CRITICAL 7.5f
#define ENTROPY_HIGH 7.0f
#define ENTROPY_MEDIUM 6.0f

#define SIGNATURE_STATE_VALID_AND_TRUSTED  0  // The signature is valid. Everything is good.
#define SIGNATURE_STATE_INVALID            1  // There is a signature, but it is invalid.
#define SIGNATURE_STATE_NOT_TRUSTED        2  // the signature is valid (homemade certificate)
#define SIGNATURE_STATE_ABSENT             3  // no signature
#define SIGNATURE_STATE_ERROR              4 // another error

typedef struct {
    char description[256];
    int score;
} HeuristicFinding;  // for description

typedef struct {
    char name[IMAGE_SIZEOF_SHORT_NAME + 1];
    DWORD virtual_address;
    DWORD virtual_size;
    DWORD raw_pointer;
    DWORD raw_size;
    float entropy;
    char flags[4];
    BOOL is_suspicious;
} SectionInfo; // section information

typedef struct {
    DWORD hash;
    const char* dll_name;
    const char* api_name;
} ApiHashInfo; 
//for hashes

// typedef struct {
//     DWORD found_hash;
//     const char* possible_api; // pointer to base
// } FoundApiHash;

typedef struct {
    char name[256];
    BOOL is_suspicious; // backlight in GUI
} FunctionInfo;  // information

typedef struct {
    char name[256];
    FunctionInfo* functions; // dynamic array of functions
    int function_count;
    int function_capacity; // for realloc control
} DllInfo; //dll structure

typedef struct {
    const char* function_name;
    int score;                 // number of points
    const char* category;      // criticality
} ApiRule; // structure for functions

typedef struct {
    BOOL is_pe;
    char verdict[32];
    int total_score;
    WORD machine_type;
    DWORD entry_point_rva;

    HeuristicFinding findings[MAX_FINDINGS];
    int finding_count;

    SectionInfo* sections;
    int section_count;

    DllInfo* dlls;
    int dll_count;
    int dll_capacity; // for realloc control

    // FoundApiHash found_hashes[50];
    // int found_hashes_count;
} AnalysisResult; //structure for analysis

BOOL analyze_pe_file(WCHAR* file_path, AnalysisResult* result); //the main function for calling the analysis
FLOAT calculate_entropy(LPVOID data_sections, DWORD size_data_sections); //entropy calculation
BOOL find_high_entropy_blocks(LPVOID data_sections, DWORD size_data_sections); //entropy calculation by blocks
VOID scan_section_for_strings(LPVOID section_data, DWORD section_size, AnalysisResult* result); // search strings
DWORD RvaToOffset(PIMAGE_NT_HEADERS p_nt_header, DWORD rva, LONGLONG file_size);
VOID evaluate_threats(PIMAGE_NT_HEADERS p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size, WCHAR* file_path, const ApiRule* dangerous_functions, size_t num_dangerous_functions);

void free_analysis_result(AnalysisResult* result);

//x64
VOID parse_sections_x64(PIMAGE_NT_HEADERS64 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size);
BOOL parse_imports_x64(PIMAGE_NT_HEADERS64 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size, const ApiRule* dangerous_functions, size_t num_dangerous_functions);

//x86
VOID parse_sections_x86(PIMAGE_NT_HEADERS32 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size);
BOOL parse_imports_x86(PIMAGE_NT_HEADERS32 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size, const ApiRule* dangerous_functions, size_t num_dangerous_functions);

static const char* suspicious_strings[] = {
    "\\Run",
    "\\RunOnce",
    "\\Winlogon",
    "powershell -enc",
    "powershell -nop",
    "powershell -w hidden",
    "powershell -executionpolicy bypass",
    "encodedcommand",
    "cmd.exe /c",
    "rundll32 ",
    "regsvr32 /s",
    "mshta http",
    "certutil -urlcache",
    "schtasks /create",
    "wevtutil cl",
    "bitsadmin /transfer",
    "Add-MpPreference -ExclusionPath",
    "vssadmin delete shadows",
    "sc stop WinDefend",
    "MpCmdRun.exe",
    "URLDownloadToFile",
    "WinHttpRequest.5.1",
    "DownloadString(",
    "FromBase64String(",
    "Invoke-Expression",
    "IEX("
};

static const ApiRule dangerous_api_rules[] = {
    // CRITICAL
    { "CreateRemoteThread",         30, "CRITICAL" },
    { "WriteProcessMemory",         30, "CRITICAL" },
    { "SetWindowsHookExA",          30, "CRITICAL" },
    { "SetWindowsHookExW",          30, "CRITICAL" },
    { "RtlCreateUserThread",        35, "CRITICAL" },
    { "VirtualAllocEx",             30, "CRITICAL" },
    { "QueueUserAPC",               25, "CRITICAL" },
    { "VirtualProtectEx",           25, "CRITICAL" },
    { "SetThreadContext",           30, "CRITICAL" },
    { "NtRaiseHardError",           40, "CRITICAL" },
    { "RtlAdjustPrivilege",         20, "CRITICAL" },
    { "AdjustTokenPrivileges",      20, "CRITICAL" },
    { "CreateProcessAsUserA",       25, "CRITICAL" },
    { "CreateProcessAsUserW",       25, "CRITICAL" },
    { "ImpersonateLoggedOnUser",    20, "CRITICAL" },
    { "NtAllocateVirtualMemory",    15, "CRITICAL" },
    { "NtProtectVirtualMemory",     15, "CRITICAL" },
    
    // HIGH
    { "LoadLibraryA",               15, "HIGH" },
    { "LoadLibraryW",               15, "HIGH" },
    { "ShellExecuteA",              20, "HIGH" },
    { "ShellExecuteW",              20, "HIGH" },
    { "CreateProcessA",             20, "HIGH" },
    { "CreateProcessW",             20, "HIGH" },
    { "system",                     20, "HIGH" },
    { "CryptEncrypt",               25, "HIGH" },
    { "CryptGenKey",                22, "HIGH" },
    { "CryptImportKey",             22, "HIGH" },
    
    // MEDIUM
    { "GetProcAddress",             3,  "MEDIUM" },
    { "InternetReadFile",           8,  "MEDIUM" },
    { "IsDebuggerPresent",          2,  "MEDIUM" },
    { "CheckRemoteDebuggerPresent", 3,  "MEDIUM" },
    { "GetTickCount",               1,  "MEDIUM" },
    { "FindWindowA",                5,  "MEDIUM" },
    { "FindWindowW",                5,  "MEDIUM" },
    { "EnumWindows",                5,  "MEDIUM" },
    { "GetAdaptersInfo",            3,  "MEDIUM" },
    { "GetComputerNameA",           2,  "MEDIUM" },
    { "GetComputerNameW",           2,  "MEDIUM" },
    { "GetAsyncKeyState",           5,  "MEDIUM" },
    { "GetKeyState",                5,  "MEDIUM" },
    { "OpenProcess",                10, "MEDIUM" },
    { "OpenThread",                 10, "MEDIUM" },
    
    // LOW
    { "Sleep",                      1, "LOW" },
    { "FindResourceA",              2, "LOW" },
    { "FindResourceW",              2, "LOW" },
    { "LoadResource",               2, "LOW" },
    { "SizeofResource",             2, "LOW" },
};

#endif
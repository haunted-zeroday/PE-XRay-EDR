#include "include/pe_analyzer.h"
#include <Softpub.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <stdlib.h>

DWORD RvaToOffset(PIMAGE_NT_HEADERS p_nt_header, DWORD rva, LONGLONG file_size)
{
    PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_nt_header);

    WORD number_of_sections = p_nt_header->FileHeader.NumberOfSections;

    for (WORD i = 0; i < number_of_sections; i++)
    {
        if (rva >= p_section_header->VirtualAddress && rva < p_section_header->VirtualAddress + p_section_header->Misc.VirtualSize)
        {
            DWORD offset = (rva - p_section_header->VirtualAddress) + p_section_header->PointerToRawData;
            if (offset >= file_size) {
                return 0;   
            }
            return offset;
        }

        p_section_header++;
    }

    return 0;
}


DWORD CheckSignature(LPCWSTR filePath)
{
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fileInfo = {0};

    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;

    WINTRUST_DATA winTrustData = {0};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &guidAction, &winTrustData);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    switch (status)
    {
    case ERROR_SUCCESS:
        return SIGNATURE_STATE_VALID_AND_TRUSTED;
    
    case TRUST_E_NOSIGNATURE:
        return SIGNATURE_STATE_ABSENT;

    case TRUST_E_BAD_DIGEST:
        return SIGNATURE_STATE_INVALID;


    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_CHAINING:
        return SIGNATURE_STATE_NOT_TRUSTED;

    default:
        return SIGNATURE_STATE_ERROR;
    }
}

FLOAT calculate_entropy(LPVOID data_sections, DWORD size_data_sections)
{
    if(size_data_sections == 0)
        return 0.0;

    DWORD counts[256];
    for (size_t i = 0; i < 256; i++)
    {
        counts[i] = 0;
    }
    BYTE* data_bytes = (BYTE*)data_sections;
    for (DWORD b = 0; b < size_data_sections; b++)
    {
        BYTE current_byte = data_bytes[b];
        counts[current_byte]++;  
    }
    FLOAT entropy = 0.0;

    for (size_t i = 0; i < 256; i++)
    {
        if (counts[i] > 0)
        {
            FLOAT p = (FLOAT)counts[i] / size_data_sections;
            entropy = entropy - (p * log2(p));
        }
    }
    return entropy;
}

BOOL find_high_entropy_blocks(LPVOID data_sections, DWORD size_data_sections)
{
    DWORD WINDOW_SIZE = 512;
    DWORD STEP_SIZE = 256;

    if (size_data_sections < WINDOW_SIZE)
        return FALSE;
    
    for (DWORD offset = 0; offset + WINDOW_SIZE <= size_data_sections; offset += STEP_SIZE)
    {
        LPVOID p_window_start = data_sections + offset;
        FLOAT entropy = calculate_entropy(p_window_start, WINDOW_SIZE);
        if (entropy > 7.4)
        {
            return TRUE;
        }
        
    }

    return FALSE;
}

VOID scan_section_for_strings(LPVOID section_data, DWORD section_size, AnalysisResult* result)
{
    size_t num_suspicious = sizeof(suspicious_strings) / sizeof(suspicious_strings[0]);

    BOOL is_reading_string = FALSE;
    BYTE* p_start_of_string = NULL; 
    DWORD current_length = 0;
    for (DWORD i = 0; i < section_size; i++)
    {
        BYTE* p_current_ptr = (BYTE*)section_data + i;
        BYTE p_current = *p_current_ptr;
        if (isprint(p_current))
        {
            if (is_reading_string == FALSE)
            {
                is_reading_string = TRUE;
                p_start_of_string = (BYTE*)section_data + i;
                current_length = 1;
            }
            else
                current_length++;
        }
        else
        {
            if (is_reading_string == TRUE)
            {
                if(p_start_of_string)
                {
                    if (current_length >= MIN_STRING_LENGTH)
                    {
                        
                        char temp_buffer[MAX_STRING_BUFFER];
                        size_t len_to_copy = (current_length < MAX_STRING_BUFFER - 1) ? current_length : MAX_STRING_BUFFER - 1;
                        memcpy(temp_buffer, p_start_of_string, len_to_copy);
                        temp_buffer[len_to_copy] = '\0';
                        
                        for (size_t j = 0; j < num_suspicious; j++)
                        {
                            if (strstr(temp_buffer, suspicious_strings[j]) != NULL)
                            {
                                if (result->finding_count < MAX_FINDINGS) 
                                {HeuristicFinding* finding = &result->findings[result->finding_count];
                                sprintf(finding->description, "[MEDIUM] Found suspicious substring '%s'", suspicious_strings[j]);
                                finding->score = 10;
                                result->finding_count++;
                                result->total_score += 10;}
                                

                                break; 
                            }
                        }
                    }
                    is_reading_string = FALSE;
                    current_length = 0;
                }
            }
        }
    }
    if (is_reading_string == TRUE && current_length >= 3)
    {
        char temp_buffer[MAX_STRING_BUFFER];
        size_t len_to_copy = (current_length < MAX_STRING_BUFFER - 1) ? current_length : MAX_STRING_BUFFER - 1;
        memcpy(temp_buffer, p_start_of_string, len_to_copy);
        temp_buffer[len_to_copy] = '\0';
        
        for (size_t j = 0; j < num_suspicious; j++)
        {
            if (strstr(temp_buffer, suspicious_strings[j]) != NULL)
            {
                if (result->finding_count < MAX_FINDINGS) 
                {HeuristicFinding* finding = &result->findings[result->finding_count];
                sprintf(finding->description, "[MEDIUM] Found suspicious substring '%s'", suspicious_strings[j]);
                finding->score = 10;
                result->finding_count++;
                result->total_score += 10;
                }

                break; 
            }
        }
        is_reading_string = FALSE;
    }
}

void AddFinding(AnalysisResult* result, int score, const char* format, ...) {
    if (result->finding_count < MAX_FINDINGS) {
        HeuristicFinding* finding = &result->findings[result->finding_count];
        finding->score = score;
        result->total_score += score;

        va_list args;
        va_start(args, format);
        vsnprintf(finding->description, sizeof(finding->description), format, args);
        va_end(args);

        result->finding_count++;
    }
}

const ApiRule* find_rule_for_function(const char* function_name, const ApiRule* rules, size_t num_rules)
{
    if (function_name == NULL || rules == NULL || num_rules == 0) {
        return NULL;
    }
    for (size_t i = 0; i < num_rules; i++)
    {
        if (strcmp(function_name, rules[i].function_name) == 0)
        {
            return &rules[i];
        }
    }
    return NULL;
}

VOID evaluate_threats(PIMAGE_NT_HEADERS p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size, WCHAR* file_path, const ApiRule* dangerous_functions, size_t num_dangerous_functions) 
{
    result->total_score = 0;
    result->finding_count = 0;

    //  section analysis
    for (int i = 0; i < result->section_count; i++) {
        SectionInfo* s = &result->sections[i];
        
        // entropy rule
        if (s->entropy > ENTROPY_CRITICAL) {
            AddFinding(result, 40, "[CRITICAL] High entropy (%.2f) in section '%s'", s->entropy, s->name);
            s->is_suspicious = TRUE;
        } else if (s->entropy > ENTROPY_HIGH) {
            AddFinding(result, 25, "[HIGH] Suspicious entropy (%.2f) in section '%s'", s->entropy, s->name);
            s->is_suspicious = TRUE;
        } else if (s->entropy > ENTROPY_MEDIUM)
        {
            AddFinding(result, 25, "[MEDIUM] Suspicious entropy (%.2f) in section '%s'", s->entropy, s->name);
            s->is_suspicious = TRUE;
        }
        
        // flag rule
        if (strstr(s->flags, "W") && strstr(s->flags, "E")) {
            AddFinding(result, 40, "[CRITICAL] Dangerous permissions (W+E) on section '%s'", s->name);
            s->is_suspicious = TRUE;
        }

        // правило на диске меньше меньше чем в памяти
        if (s->raw_size == 0 && s->virtual_size > 500 * 1024) {
            AddFinding(result, 50, "[CRITICAL] Section '%s' has 0 size on disk but large in memory", s->name);
            s->is_suspicious = TRUE;
        }

        // block entropy rule
        if (s->entropy < 7.0f && s->raw_size > 1024) {
            BYTE* data = (BYTE*)lp_base_address + s->raw_pointer;
            if (find_high_entropy_blocks(data, s->raw_size)) {
                AddFinding(result, 50, "[CRITICAL] Found hidden high-entropy block in section '%s'", s->name);
                s->is_suspicious = TRUE;
            }
        }
    }

    //  entrypoint analysis
    DWORD entryPointRVA = result->entry_point_rva;
    BOOL entry_point_found = FALSE;
    SectionInfo* entry_point_section = NULL;

    for (int i = 0; i < result->section_count; i++) {
        if (entryPointRVA >= result->sections[i].virtual_address && entryPointRVA < result->sections[i].virtual_address + result->sections[i].virtual_size) {
            entry_point_found = TRUE;
            entry_point_section = &result->sections[i];
            break;
        }
    }

    if (!entry_point_found) {
        AddFinding(result, 50, "[CRITICAL] Entry point is outside of any section");
    } else {
        if (!strstr(entry_point_section->flags, "E")) {
            AddFinding(result, 40, "[HIGH] Entry point is in a non-executable section ('%s')", entry_point_section->name);
        }
        if (strncmp(entry_point_section->name, ".text", 5) != 0) {
            AddFinding(result, 20, "[MEDIUM] Entry point is not in .text section (it's in '%s')", entry_point_section->name);
        }
    }
    // import analysis
    for (int i = 0; i < result->dll_count; i++) {
        for (int j = 0; j < result->dlls[i].function_count; j++) {

            
            if (result->dlls[i].functions[j].is_suspicious) 
            {
                const char* func_name = result->dlls[i].functions[j].name;
                const ApiRule* rule = find_rule_for_function(func_name, dangerous_functions, num_dangerous_functions);

                if (rule) {
                    AddFinding(result, rule->score, "[%s] Suspicious import: %s", rule->category, rule->function_name);
                }
                else {
                    AddFinding(result, 5, "[LOW] Suspicious import (no rule): %s", func_name);
                }
            }
        }
    }
    // count dlls
    if (result->dll_count >= 0 && result->dll_count < 3) 
    {
        AddFinding(result, 20, "Anomalously low DLL count: %d (likely packed)", result->dll_count);
    }

    // string parsing
    for (int i = 0; i < result->section_count; i++) {
        if (strncmp(result->sections[i].name, ".rdata", 6) == 0 || strncmp(result->sections[i].name, ".data", 5) == 0) {
             BYTE* data = (BYTE*)lp_base_address + result->sections[i].raw_pointer;
             scan_section_for_strings(data, result->sections[i].raw_size, result);
        }
    }


    // final verdict
    if (result->total_score > 250) {
        sprintf(result->verdict, "Critical risk");
    }
    else if (result->total_score > 140) {
        sprintf(result->verdict, "High risk");
    }
    else if (result->total_score > 80) {
        sprintf(result->verdict, "Medium risk");
    }
    else if (result->total_score > 50) {
        sprintf(result->verdict, "Low risk");
    }
    else {
        sprintf(result->verdict, "Clean");
    }
    
    
    DWORD signatureStatus = CheckSignature(file_path);
    if (signatureStatus == SIGNATURE_STATE_VALID_AND_TRUSTED)
    {
        result->total_score = 0;
        strcpy(result->verdict, "Trusted");
        result->finding_count = 0; 
        
        HeuristicFinding* finding = &result->findings[result->finding_count++];
        sprintf(finding->description, "[TRUSTED] The file has a valid digital signature.");
        finding->score = 0;
    }
    else if (signatureStatus == SIGNATURE_STATE_INVALID)
    {
        AddFinding(result, 100, "[CRITICAL] The digital signature is corrupted.");
    }
    else if (signatureStatus == SIGNATURE_STATE_NOT_TRUSTED)
    {
        AddFinding(result, 40, "[HIGH] The digital signature was made independently.");
    }
}

void free_analysis_result(AnalysisResult* result)
{
    if (result == NULL) return;

    if (result->sections) {
        free(result->sections);
        result->sections = NULL; 
    }

    if (result->dlls) {
        for (int i = 0; i < result->dll_count; i++) {
            if (result->dlls[i].functions) {
                free(result->dlls[i].functions);
            }
        }
        free(result->dlls);
        result->dlls = NULL;
    }

    result->section_count = 0;
    result->dll_count = 0;
    result->finding_count = 0;
    result->total_score = 0;
}


BOOL analyze_pe_file(WCHAR* file_path, AnalysisResult* result)
{
    memset(result, 0, sizeof(AnalysisResult));

    HANDLE h_file = INVALID_HANDLE_VALUE; 
    h_file = CreateFileW(file_path, GENERIC_READ, 0, NULL, 3, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_file == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(h_file, &file_size)) {
        CloseHandle(h_file);
        return FALSE;
    }

    LONGLONG li_file_size = file_size.QuadPart;

    // const LONGLONG MAX_FILE_SIZE = 20 * 1024 * 1024; 

    // if (file_size.QuadPart > MAX_FILE_SIZE) {
    //     sprintf(result->verdict, "Файл больше (> %d MB)", MAX_FILE_SIZE / 1024 / 1024);
    //     CloseHandle(h_file);
    //     return FALSE;
    // }

    if (file_size.QuadPart == 0) {
        sprintf(result->verdict, "File is empty");
        CloseHandle(h_file);
        return FALSE;
    }

    


    HANDLE h_map_object = CreateFileMappingW(h_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (h_map_object == NULL)
    {
        CloseHandle(h_map_object);
        return FALSE;
    }

    LPVOID lp_base_address = MapViewOfFile(h_map_object, FILE_MAP_READ, 0, 0, 0); //we get the entry address through mapping
    if(lp_base_address == NULL)
    {
        CloseHandle(h_map_object);
        CloseHandle(h_file);
        return FALSE;
    }
    
    PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)lp_base_address; // we get a DOS header

    if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        UnmapViewOfFile(lp_base_address);
        CloseHandle(h_map_object);
        CloseHandle(h_file);
        return FALSE;
    }

    if (p_dos_header->e_lfanew <= 0 || p_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) > file_size.QuadPart)
    {
        sprintf(result->verdict, "Invalid PE header");
        return FALSE;
    }

    PIMAGE_NT_HEADERS p_nt_header = (PIMAGE_NT_HEADERS)((BYTE*)lp_base_address + p_dos_header->e_lfanew); // shift to PIMAGE_NT_HEADERS
    if (p_nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        UnmapViewOfFile(lp_base_address);
        CloseHandle(h_map_object);
        CloseHandle(h_file);
        return FALSE;
    }

    result->is_pe = TRUE;
    result->machine_type = p_nt_header->FileHeader.Machine;

    PIMAGE_FILE_HEADER p_file_header = &(p_nt_header->FileHeader);

    //API rules (functions). The list of functions can be found in pe_analyzer.h

    size_t num_dangerous = sizeof(dangerous_api_rules) / sizeof(dangerous_api_rules[0]); //for counter  


    if (p_file_header->Machine == IMAGE_FILE_MACHINE_I386)
    {
        PIMAGE_NT_HEADERS32 p_nt_header32 = (PIMAGE_NT_HEADERS32)p_nt_header;
        
        result->entry_point_rva = p_nt_header32->OptionalHeader.AddressOfEntryPoint;

        parse_sections_x86(p_nt_header32, lp_base_address, result, li_file_size);
        parse_imports_x86(p_nt_header32, lp_base_address, result, li_file_size, dangerous_api_rules, num_dangerous);
    }
    else if(p_file_header->Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        PIMAGE_NT_HEADERS64 p_nt_header64 = (PIMAGE_NT_HEADERS64)p_nt_header;

        result->entry_point_rva = p_nt_header64->OptionalHeader.AddressOfEntryPoint;

        parse_sections_x64(p_nt_header64, lp_base_address, result, li_file_size);
        parse_imports_x64(p_nt_header64, lp_base_address, result, li_file_size, dangerous_api_rules, num_dangerous);
    }
    else
    {
        return FALSE;
    }

    evaluate_threats(p_nt_header, lp_base_address, result, li_file_size, file_path, dangerous_api_rules, num_dangerous);
    
    
    // clear handles
    UnmapViewOfFile(lp_base_address);
    CloseHandle(h_map_object);
    CloseHandle(h_file);
    
    return TRUE;
}
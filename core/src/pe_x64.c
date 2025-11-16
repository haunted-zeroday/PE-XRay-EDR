#include "../include/pe_analyzer.h"

VOID parse_sections_x64(PIMAGE_NT_HEADERS64 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size)
{
    WORD number_of_sections = p_nt_header->FileHeader.NumberOfSections;
    if (number_of_sections == 0 || number_of_sections > 96) {
        result->section_count = 0;
        result->sections = NULL;
        return;
    }

    result->section_count = number_of_sections;
    result->sections = (SectionInfo*)malloc(number_of_sections * sizeof(SectionInfo));
    if (!result->sections) {
        result->section_count = 0;
        return;
    }

    PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_nt_header);

    for (WORD i = 0; i < number_of_sections; i++)
    {
        SectionInfo* current_section = &result->sections[i];
        memset(current_section, 0, sizeof(SectionInfo));

        strncpy(current_section->name, (char*)p_section_header->Name, IMAGE_SIZEOF_SHORT_NAME);
        current_section->name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
        
        current_section->virtual_address = p_section_header->VirtualAddress;
        current_section->virtual_size = p_section_header->Misc.VirtualSize;

        current_section->raw_pointer = p_section_header->PointerToRawData;
        current_section->raw_size = p_section_header->SizeOfRawData;
        
        current_section->flags[0] = (p_section_header->Characteristics & IMAGE_SCN_MEM_READ) ? 'R' : '-';
        current_section->flags[1] = (p_section_header->Characteristics & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
        current_section->flags[2] = (p_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';
        current_section->flags[3] = '\0';

        if (p_section_header->PointerToRawData + p_section_header->SizeOfRawData > file_size || p_section_header->SizeOfRawData == 0) {
            current_section->entropy = 0.0f;
            current_section->is_suspicious = TRUE;
        } else {
            BYTE* data_sections = (BYTE*)lp_base_address + p_section_header->PointerToRawData;
            DWORD size_data_sections = p_section_header->SizeOfRawData;
            current_section->entropy = calculate_entropy(data_sections, size_data_sections);
        }

        p_section_header++;
    }
}

BOOL parse_imports_x64(PIMAGE_NT_HEADERS64 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size, const ApiRule* dangerous_functions, size_t num_dangerous_functions)
{
    result->dlls = NULL;
    result->dll_count = 0;
    
    DWORD import_rva = p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva == 0) {
        return TRUE;
    }

    DWORD import_offset = RvaToOffset((PIMAGE_NT_HEADERS)p_nt_header, import_rva, file_size);
    if (import_offset == 0) {
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR p_import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)lp_base_address + import_offset);

    result->dll_capacity = 8; 
    result->dlls = (DllInfo*)malloc(result->dll_capacity * sizeof(DllInfo));
    if (!result->dlls) { return FALSE; }

    // loop under dll
    while (p_import_descriptor->Name != 0)
    {
        if (result->dll_count >= result->dll_capacity) {
            result->dll_capacity *= 2;
            DllInfo* new_dlls = (DllInfo*)realloc(result->dlls, result->dll_capacity * sizeof(DllInfo));
            if (!new_dlls) { free(result->dlls); return FALSE; }
            result->dlls = new_dlls;
        }

        DllInfo* current_dll = &result->dlls[result->dll_count];
        memset(current_dll, 0, sizeof(DllInfo));

        DWORD dll_name_offset = RvaToOffset((PIMAGE_NT_HEADERS)p_nt_header, p_import_descriptor->Name, file_size);
        if (dll_name_offset != 0) {
            strncpy(current_dll->name, (char*)((BYTE*)lp_base_address + dll_name_offset), sizeof(current_dll->name) - 1);
        }

        // loop for functions 
        DWORD thunk_rva = p_import_descriptor->OriginalFirstThunk ? p_import_descriptor->OriginalFirstThunk : p_import_descriptor->FirstThunk;
        DWORD thunk_offset = RvaToOffset((PIMAGE_NT_HEADERS)p_nt_header, thunk_rva, file_size);
        
        if (thunk_offset != 0) {
            current_dll->function_capacity = 16;
            current_dll->functions = (FunctionInfo*)malloc(current_dll->function_capacity * sizeof(FunctionInfo));
            if (!current_dll->functions) { continue; }

            PIMAGE_THUNK_DATA64 p_thunk_data = (PIMAGE_THUNK_DATA64)((BYTE*)lp_base_address + thunk_offset);
            
            while (p_thunk_data->u1.AddressOfData != 0) {
                if (current_dll->function_count >= current_dll->function_capacity) {
                    current_dll->function_capacity *= 2;
                    FunctionInfo* new_funcs = (FunctionInfo*)realloc(current_dll->functions, current_dll->function_capacity * sizeof(FunctionInfo));
                    if(!new_funcs) { break; }
                    current_dll->functions = new_funcs;
                }

                FunctionInfo* current_func = &current_dll->functions[current_dll->function_count];
                memset(current_func, 0, sizeof(FunctionInfo));

                if (!(p_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    DWORD func_name_offset = RvaToOffset((PIMAGE_NT_HEADERS)p_nt_header, (DWORD)p_thunk_data->u1.AddressOfData, file_size);
                    if (func_name_offset != 0) {
                        PIMAGE_IMPORT_BY_NAME p_import_by_name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)lp_base_address + func_name_offset);
                        strncpy(current_func->name, p_import_by_name->Name, sizeof(current_func->name) - 1);

                        for (size_t i = 0; i < num_dangerous_functions; i++) {
                            if (strcmp(current_func->name, dangerous_functions[i].function_name) == 0) {
                                current_func->is_suspicious = TRUE;
                                break;
                            }
                        }
                    }
                } else {
                    sprintf(current_func->name, "Ordinal %llu", p_thunk_data->u1.Ordinal & 0xFFFF);
                }
                
                current_dll->function_count++;
                p_thunk_data++;
            }
        }
        
        result->dll_count++;
        p_import_descriptor++;
    }
    
    return TRUE;
}
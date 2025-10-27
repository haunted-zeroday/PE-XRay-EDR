
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlwapi.h>

#include "core/include/pe_analyzer.h"
#include "include/addons.h"

void print_analysis_results_cli(const AnalysisResult* result) {
    if (!result) {
        printf("No analysis data available.\n");
        return;
    }

    printf("======================================\n");
    printf("         PE-XRay Analysis Report      \n");
    printf("======================================\n\n");

    printf("Verdict: %s\n", result->verdict);
    printf("Total Score: %d\n\n", result->total_score);

    printf("--- Findings ---\n");
    if (result->finding_count > 0) {
        for (int i = 0; i < result->finding_count; i++) {
            printf("- [%d pts] %s\n", result->findings[i].score, result->findings[i].description);
        }
    } else {
        printf("No suspicious findings.\n");
    }
    printf("\n");
    printf("--- Sections ---\n");
    if (result->section_count > 0) {
        printf("%-10s | %-12s | %-10s | %-10s | %s\n", "Name", "Address", "Size", "Entropy", "Flags");
        printf("--------------------------------------------------------------------------------\n");
        for (int i = 0; i < result->section_count; i++) {
            printf("%-10s | 0x%08X   | %-10u | %-10.2f | %s %s\n",
                   result->sections[i].name,
                   result->sections[i].virtual_address,
                   result->sections[i].virtual_size,
                   result->sections[i].entropy,
                   result->sections[i].flags,
                   result->sections[i].is_suspicious ? "[SUSPICIOUS]" : "");
        }
    } else {
        printf("No section data found.\n");
    }
    printf("\n");
    printf("--- Imports ---\n");
    if (result->dll_count > 0) {
        for (int i = 0; i < result->dll_count; i++) {
            printf("  DLL: %s\n", result->dlls[i].name);
            for (int j = 0; j < result->dlls[i].function_count; j++) {
                printf("    -> %s %s\n",
                       result->dlls[i].functions[j].name,
                       result->dlls[i].functions[j].is_suspicious ? "[SUSPICIOUS]" : "");
            }
            printf("\n");
        }
    } else {
        printf("No import data found.\n");
    }
}

void print_usage(const char* app_name) {
    printf("PE-XRay Command-Line Analyzer\n");
    printf("Usage:\n");
    printf("  %s <path_to_file.exe_or_dll>   : Analyze a file.\n", app_name);
    printf("  %s --install                   : Enable context menu integration (needs admin rights).\n", app_name);
    printf("  %s --uninstall                 : Disable context menu integration (needs admin rights).\n", app_name);
    printf("  %s --help                      : Show this help message.\n", app_name);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    char* command = argv[1];

    if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(command, "--install") == 0) {
        if (enable_integration_all()) {
            printf("Context menu integration enabled successfully.\n");
            return 0;
        } else {
            fprintf(stderr, "Failed to enable integration. Try running as Administrator.\n");
            return 1;
        }
    }

    if (strcmp(command, "--uninstall") == 0) {
        if (disable_integration_all()) {
            printf("Context menu integration disabled successfully.\n");
            return 0;
        } else {
            fprintf(stderr, "Failed to disable integration. Try running as Administrator.\n");
            return 1;
        }
    }
    char* filePathUtf8 = command;
    printf("Analyzing file: %s\n\n", filePathUtf8);

    WCHAR* filePathWchar = ConvertUtf8ToWchar(filePathUtf8);
    if (!filePathWchar) {
        fprintf(stderr, "Error: Could not convert file path to wide string.\n");
        return 1;
    }

    AnalysisResult result_data;
    memset(&result_data, 0, sizeof(AnalysisResult));

    if (analyze_pe_file(filePathWchar, &result_data)) {
        print_analysis_results_cli(&result_data);
    } else {
        fprintf(stderr, "Error: Failed to analyze the PE file. It might be corrupted or not a PE file.\n");
    }

    free(filePathWchar);
    free_analysis_result(&result_data);

    return 0;
}
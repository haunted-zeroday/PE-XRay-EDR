#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <locale.h>
#include "../include/scanner.h"

#define UNICODE
#define _UNICODE

// int FindRecursive(const WCHAR* path)
// {
//     WIN32_FIND_DATAW ffd;
//     LARGE_INTEGER filesize;
//     WCHAR szDir[MAX_PATH];
//     size_t length_of_arg;
//     HANDLE hFind = INVALID_HANDLE_VALUE;
//     WCHAR nextPath[MAX_PATH];

//     StringCchLengthW(path, MAX_PATH, &length_of_arg);

//     if (length_of_arg > (MAX_PATH - 3))
//     {
//         return (-1);
//     }


//     StringCchCopyW(szDir, MAX_PATH, path);
//     StringCchCatW(szDir, MAX_PATH, L"\\*");

//     hFind = FindFirstFileW(szDir, &ffd);

//     if (INVALID_HANDLE_VALUE == hFind) 
//     {
//         return 0;
//     } 

//     do
//     {
//         if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
//         {
//             //если директория
//             if (wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0) //
//             {
//             StringCchPrintfW(nextPath, MAX_PATH, L"%s\\%s", path, ffd.cFileName);
//             char *convert =  ConvertWcharToUtf8(nextPath);
//             free(convert);
//             //сама рекурсия
//             FindRecursive(nextPath);
//             }
//         }
//         else
//         { //если атрибуты != директория (файл)
//             filesize.LowPart = ffd.nFileSizeLow;
//             filesize.HighPart = ffd.nFileSizeHigh;
//             StringCchPrintfW(nextPath, MAX_PATH, L"%s\\%s", path, ffd.cFileName);
            
//             // тут логика самого антивиря
//         }
//     }
//     while (FindNextFileW(hFind, &ffd) != 0);

//     FindClose(hFind);
//     return 0;
// }

char* ConvertWcharToUtf8(WCHAR* wideString) //конвертация в utf8 из utf-16
{
    if (wideString == NULL) {
        return NULL;
    }

    int requiredSize = WideCharToMultiByte(
        CP_UTF8,
        0,
        wideString,
        -1,
        NULL,
        0,
        NULL,
        NULL
    );

    if (requiredSize == 0) {
        return NULL;
    }

    char* utf8String = (char*)malloc(requiredSize);
    if (utf8String == NULL) {
        return NULL;
    }

    int result = WideCharToMultiByte(
        CP_UTF8,
        0,
        wideString,
        -1,
        utf8String,
        requiredSize,
        NULL,
        NULL
    );

    if (result == 0) {
        free(utf8String);
        return NULL;
    }

    return utf8String;
}

WCHAR* ConvertUtf8ToWchar(char* utf8String) 
{
    if (utf8String == NULL) {
        return NULL;
    }

    int requiredSize = MultiByteToWideChar(
        CP_UTF8,
        0,
        utf8String,
        -1,
        NULL,
        0
    );

    if (requiredSize == 0) {
        return NULL;
    }
    WCHAR* wideString = (WCHAR*)malloc(requiredSize * sizeof(WCHAR));
    if (wideString == NULL) {
        return NULL;
    }
    int result = MultiByteToWideChar(
        CP_UTF8,
        0,
        utf8String,
        -1,
        wideString,
        requiredSize
    );

    if (result == 0) {
        free(wideString);
        return NULL;
    }
    return wideString;
}
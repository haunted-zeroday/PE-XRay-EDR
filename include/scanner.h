#ifndef SCANNER_H
#define SCANNER_H

#include <windows.h>

int FindRecursive(const WCHAR* path);
char* ConvertWcharToUtf8(WCHAR* wideString);
WCHAR* ConvertUtf8ToWchar(char* utf8String);

#endif
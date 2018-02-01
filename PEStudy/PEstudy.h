#ifndef PESTUDY_H
#define PEDTUDY_H
#include <windows.h>
bool isPEFile(LPVOID ImageBase);
PIMAGE_NT_HEADERS getNtHeaders(LPVOID ImageBase);
PIMAGE_FILE_HEADER WINAPI getFileHeader(PIMAGE_NT_HEADERS pNtH);
PIMAGE_OPTIONAL_HEADER32 WINAPI getOptionalHeader(PIMAGE_NT_HEADERS pNtH);
PIMAGE_SECTION_HEADER getFirstSectionHeader(PIMAGE_NT_HEADERS pNtH);

LPVOID RvaToPtr(PIMAGE_NT_HEADERS pNtH, LPVOID ImageBase, DWORD dwRVA);

void showFileHeader(PIMAGE_FILE_HEADER pFH);
void showOptionalHeader(PIMAGE_OPTIONAL_HEADER32 pOH);
void showSectionHeader(PIMAGE_SECTION_HEADER pSH, int numberOfSections);
#endif

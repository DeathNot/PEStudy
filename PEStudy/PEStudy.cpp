#include "PEStudy.h"
#include <iostream>
#include <ctime>
#include <ImageHlp.h>

#pragma warning(disable:4996)
#pragma comment(lib, "imagehlp.lib")

bool isPEFile(LPVOID ImageBase) {
	PIMAGE_DOS_HEADER   pDH = NULL;
	PIMAGE_NT_HEADERS    pNtH = NULL;

	if (!ImageBase)       //判断印象基址
		return FALSE;
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)  //判断是否为MZ
		return FALSE;
	pNtH = (PIMAGE_NT_HEADERS32)((DWORD)pDH + pDH->e_lfanew);  //判断是否为PE格式
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	return TRUE;
}

PIMAGE_NT_HEADERS getNtHeaders(LPVOID ImageBase) {
	PIMAGE_DOS_HEADER	pDH = NULL;
	PIMAGE_NT_HEADERS	pNtH = NULL;

	if (!isPEFile(ImageBase))
		return NULL;
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	return pNtH;
}

PIMAGE_FILE_HEADER WINAPI getFileHeader(PIMAGE_NT_HEADERS pNtH) {
	if (!pNtH)
		return NULL;
	PIMAGE_FILE_HEADER pFH = &pNtH->FileHeader;
	return pFH;
}

PIMAGE_OPTIONAL_HEADER32 WINAPI getOptionalHeader(PIMAGE_NT_HEADERS pNtH) {
	if (!pNtH)
		return NULL;
	PIMAGE_OPTIONAL_HEADER32	pOH = &pNtH->OptionalHeader;
	return pOH;
}

PIMAGE_SECTION_HEADER getFirstSectionHeader(PIMAGE_NT_HEADERS pNtH) {
	PIMAGE_SECTION_HEADER pSH;
	pSH = IMAGE_FIRST_SECTION(pNtH);
	return pSH;
}

void showFileHeader(PIMAGE_FILE_HEADER pFH) {
	if (pFH) {
		std::cout << std::hex << "Machine: " << pFH->Machine << std::endl;
		std::cout << "NumberOfSections: " << pFH->NumberOfSections << std::endl;
		time_t	timep;
		timep = (time_t)pFH->TimeDateStamp;
		std::cout << "TimeDateStamp: " << ctime(&timep);
		std::cout << "SizeOfOptionalHeader: " << pFH->SizeOfOptionalHeader << std::endl;
		std::cout << "Characteristics: " << pFH->Characteristics << std::endl;
	}
	else
		std::cout << "Input pFH error!" << std::endl;
}

LPVOID RvaToPtr(PIMAGE_NT_HEADERS pNtH, LPVOID ImageBase, DWORD dwRVA) {
	return ImageRvaToVa(pNtH, ImageBase, dwRVA, NULL);
}

void showSectionHeader(PIMAGE_SECTION_HEADER pSH, int numberOfSections) {
	if (!pSH)
		return;
	for (int i = 0; i < numberOfSections; i++) {
		std::cout << pSH->Name << std::endl;
		pSH++;
	}
}

void showOptionalHeader(PIMAGE_OPTIONAL_HEADER32 pOH) {
	if (!pOH)
		return;
	std::cout << "AddressOfEntryPoint: " << pOH->AddressOfEntryPoint << std::endl; //文件被执行时的入口地址RVA
	std::cout << "ImageBase: " << pOH->ImageBase << std::endl; //文件的优先装入地址
	std::cout << "FileAlignment: " << pOH->FileAlignment << std::endl; //节存储在磁盘文件中时的对齐单位
	std::cout << "SectionAlignment: " << pOH->SectionAlignment << std::endl; //节被装入内存后的对齐单位

}
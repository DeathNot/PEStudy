#include <fstream>
#include <string>
#include <iostream>
#include <cstdlib>
#include "PEStudy.h"

using namespace std;

int main() {
	string		filename;
	cin >> filename;

	ifstream	fin;
	fin.open(filename, ios::binary);
	if (!fin.is_open()) {  //判断是否成功打开PE文件
		cout << "Open file failed!" << endl;
		exit(1);
	} 

	fin.seekg(0, ios::end);
	int fileSize = fin.tellg();
	fin.seekg(0, ios::beg);
	char *pBuf = new char[fileSize];
	fin.read(pBuf, fileSize);
	if (!isPEFile(pBuf)) {
		cout << "The file is not a PE file!" << endl;
		exit(1);
	}
	
	PIMAGE_NT_HEADERS pNtH = getNtHeaders(pBuf);
	PIMAGE_FILE_HEADER pFH = getFileHeader(pNtH);
	PIMAGE_OPTIONAL_HEADER32	pOH = getOptionalHeader(pNtH);
	PIMAGE_SECTION_HEADER pSH = getFirstSectionHeader(pNtH);

	int numberOfSections = pFH->NumberOfSections;
	showFileHeader(pFH);
	showOptionalHeader(pOH);
	showSectionHeader(pSH, numberOfSections);

	delete [] pBuf;
	fin.close();
	return 0;
}

#include<windows.h>
#include<iostream>
#include<imagehlp.h>
#include"PETools.h"

int main() {
	DWORD fileSize = 0;
	char path[] = "C:\\Users\\admin\\source\\repos\\PE_Tls\\Debug\\PE_SEH.exe";
	char apiName[] = "printf";
	WCHAR dllName[] = L"PEDump.exe";
	DWORD imageBase = OpenFile_PE(&fileSize, path);
	BOOL  state = checkDllVersion(imageBase);
	if (imageBase == NULL || !state) {
		return 0;
	}
	DWORD dwPEB = 0;
	_asm {
		mov eax,fs:[0x30];
		mov dwPEB, eax;
	}
	CompressPE(imageBase, fileSize);
	system("pause");
	return 0;
}
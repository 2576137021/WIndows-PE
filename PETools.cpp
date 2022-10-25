#include"PETools.h"
//��ʾ
void printfLine(char* buffer, int lineNumber, int remainder) {

	int dwLineNumber = 0x0;
	char szThreeLine[17] = { 0 };
	while (lineNumber != 0)
	{
		printf("%08x\t", dwLineNumber);
		memset(szThreeLine, 0, 17);
		for (size_t i = 0; i < 16; i++)
		{
			BYTE oneByte = *(BYTE*)buffer;
			if (oneByte >= 0x20 && oneByte <= 0x7A) {
				char tempLine[2] = { 0 };
				tempLine[0] = *buffer;
				strcat(szThreeLine, tempLine);
			}
			else
			{
				const char* tempLine = ".";
				strcat(szThreeLine, tempLine);
			}
			printf("%02x ", oneByte);
			buffer++;
		}
		printf("\t%s\n", szThreeLine);
		lineNumber--;
		dwLineNumber += 0x10;
	}
	if (remainder != 0) {
		printf("%08x\t", dwLineNumber);
		memset(szThreeLine, 0, 17);
		for (size_t i = 0; i < remainder; i++)
		{
			BYTE oneByte = *(BYTE*)buffer;
			if (oneByte >= 0x20 && oneByte <= 0x7A) {
				char tempLine[2] = { 0 };
				tempLine[0] = *buffer;
				strcat(szThreeLine, tempLine);
			}
			else
			{
				const char* tempLine = ".";
				strcat(szThreeLine, tempLine);
			}
			printf("%02x ", oneByte);
			buffer++;
		}
		printf("%*s", (16 - remainder) * 3, "");
		printf("\t%s\n", szThreeLine);
	}
}
int Pedump() {

	char FilePath[0x200];
	printf("�������ļ�����·��:");
	scanf("%s", FilePath);
	HANDLE handle = CreateFileA(FilePath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE) {
		printf("���ļ�ʧ�� %d\n", GetLastError());
		return 0;
	}
	DWORD dwFileSize = 0;
	DWORD readSize = 0;
	dwFileSize = GetFileSize(handle, NULL);
	PVOID fileBuffer = calloc(dwFileSize, 1);
	BOOL state = ReadFile(handle, fileBuffer, dwFileSize, &readSize, NULL);
	if (state == FALSE) {
		printf("��ȡ�ļ�ʧ�� %d\n", GetLastError());
		return 0;
	}
	int LineNumber = dwFileSize / 16;
	int remainder = dwFileSize % 16;
	printfLine((char*)fileBuffer, LineNumber, remainder);
	system("pause");
}
DWORD OpenFile_PE(DWORD* dwRetFileSize, char* szFilePath) {
	char FilePathss[0x200];
	char* FilePath;
	FilePath = FilePathss;
	if (szFilePath == NULL) {

		printf("�������ļ�����·��:");
		scanf("%s", FilePath);
	}
	else
	{
		FilePath = szFilePath;
	}
	DWORD HeaderSum = 0;
	DWORD CheckSum = 0;
	MapFileAndCheckSumA(FilePath, &HeaderSum, &CheckSum);
	printf("HeaderSum:%x,CheckSum:%x\n", HeaderSum, CheckSum);

	HANDLE handle = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_WRITE| FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE) {
		printf("���ļ�ʧ�� %d\n", GetLastError());
		return 0;
	}
	DWORD dwFileSize = 0;
	DWORD readSize = 0;
	dwFileSize = GetFileSize(handle, NULL);
	PVOID fileBuffer = calloc(dwFileSize, 1);
	BOOL state = ReadFile(handle, fileBuffer, dwFileSize, &readSize, NULL);
	if (state == FALSE) {
		printf("��ȡ�ļ�ʧ�� %d\n", GetLastError());
		return 0;
	}
	*dwRetFileSize = dwFileSize;
	CloseHandle(handle);
	return (DWORD)fileBuffer;
}
DWORD RvatoFoa(DWORD imagebase, DWORD rva) {

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imagebase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(imagebase + dosHeader->e_lfanew);
	IMAGE_FILE_HEADER pFileHeader = pHeader->FileHeader;
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pHeader);
	DWORD foa = NULL;
	for (size_t i = 0; i < pFileHeader.NumberOfSections; i++)
	{
		if (rva >= sectionHeader->VirtualAddress && rva < sectionHeader->Misc.VirtualSize + sectionHeader->VirtualAddress) {
			foa = rva - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
			return foa;
		}
		sectionHeader++;
	}

	printf("RvatoFoa Error\n");
	return foa;
}
DWORD CalcCheckSum(DWORD imagebase, DWORD dwFileSize) {

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imagebase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(imagebase + dosHeader->e_lfanew);
	//У�������
	pHeader->OptionalHeader.CheckSum = 0;
	DWORD dwTempFileSize = dwFileSize;
	WORD counttemp = 0;
	for (size_t i = 0; i <= dwFileSize / 2; i++)
	{
		//��WORDΪ��λ�����ݿ���д���λ���ۼ�
		//�ۼӼ����ļ��ĳ���
		counttemp += *(WORD*)imagebase;
		imagebase += 2;
	}
	dwTempFileSize = counttemp + dwTempFileSize;
	return dwTempFileSize;
}
void improtTable(DWORD dwImageBase, int dwFlag) {
	PIMAGE_DOS_HEADER			dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS			pHHt = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY		pDataDir = pHHt->OptionalHeader.DataDirectory[1];
	PIMAGE_IMPORT_DESCRIPTOR	pImport = (PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + RvatoFoa(dwImageBase, pDataDir.VirtualAddress));;
	DWORD temp;
	if (dwFlag == 1) {
		temp = pImport->FirstThunk;
	}
	else
	{
		temp = pImport->OriginalFirstThunk;
	}
	while (pImport->Characteristics != 0)
	{

		DWORD dllNameAddr = dwImageBase + RvatoFoa(dwImageBase, pImport->Name);
		PIMAGE_THUNK_DATA TData = (PIMAGE_THUNK_DATA)(dwImageBase + RvatoFoa(dwImageBase, temp));
		printf("-------------------%s------------------\n", dllNameAddr);
		while (TData->u1.AddressOfData != 0)
		{
			PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(dwImageBase + RvatoFoa(dwImageBase, TData->u1.Function));
			printf("%s\t\n", importByName->Name);
			TData++;
		}
		pImport++;
	}


}
DWORD32 GetIATAddr(DWORD32 dwImageBase) {
	PIMAGE_DOS_HEADER			dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS			pHHt = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY		pDataDir = pHHt->OptionalHeader.DataDirectory[1];
	PIMAGE_IMPORT_DESCRIPTOR	pImport = (PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + RvatoFoa(dwImageBase, pDataDir.VirtualAddress));;
	DWORD32  a = pHHt->OptionalHeader.ImageBase;
	return  a + pImport->FirstThunk;
}
DWORD FoaToRva(DWORD imagebase, DWORD foa) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imagebase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(imagebase + dosHeader->e_lfanew);
	IMAGE_FILE_HEADER pFileHeader = pHeader->FileHeader;
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pHeader);
	for (size_t i = 0; i < pFileHeader.NumberOfSections; i++)
	{
		if (foa >= sectionHeader->PointerToRawData && foa < sectionHeader->SizeOfRawData + sectionHeader->PointerToRawData) {
			DWORD rva = foa - sectionHeader->PointerToRawData + sectionHeader->VirtualAddress;
			return rva;
		}
		sectionHeader++;
	}
	printf("FoaToRva Error\n");
	return NULL;

}
/*
�������һ����, �����޸����һ����Ϊ�ɶ���д����
�޸�optionHandle�е����һ���ڱ�Ĵ�С��
����:�����ĵ�ַָ��
*/
DWORD ExpandLastSection(DWORD dwImageBase, DWORD fileSize, DWORD dwExpandSize) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pHeader);
	PIMAGE_SECTION_HEADER pLastSection = &pFirstSection[pHeader->FileHeader.NumberOfSections - 1];
	//�޸�Ϊ�ɶ���д
	pLastSection->Characteristics |= 0xC0000000;
	DWORD newImageBase = (DWORD)calloc(fileSize + dwExpandSize, 1);
	//�޸�pe�ֶ�
	pLastSection->SizeOfRawData += dwExpandSize;
	pLastSection->Misc.VirtualSize += (dwExpandSize / pHeader->OptionalHeader.SectionAlignment + 1) * pHeader->OptionalHeader.SectionAlignment;
	pHeader->OptionalHeader.SizeOfImage += (dwExpandSize / pHeader->OptionalHeader.SectionAlignment + 1) * pHeader->OptionalHeader.SectionAlignment;
	memcpy((PVOID)newImageBase, (PVOID)dwImageBase, fileSize);
	return newImageBase;
}
//�޸ĵ����
BOOL ModifiImprot(char* szFileName, char* szDllName, char* szApiName) {
	DWORD fileSize = 0;
	DWORD imageBase = OpenFile_PE(&fileSize, szFileName);
	if (imageBase == NULL) {
		return FALSE;
	}
	//��ȡ��ǰ�����Ĵ�С
	DWORD dwImprotCount = 0;
	PIMAGE_DOS_HEADER hdos = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS hnt = (PIMAGE_NT_HEADERS)(imageBase + hdos->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR hImport = PIMAGE_IMPORT_DESCRIPTOR(imageBase + RvatoFoa(imageBase, hnt->OptionalHeader.DataDirectory[1].VirtualAddress));
	PIMAGE_IMPORT_DESCRIPTOR hTempImport = hImport;
	while (hTempImport->Characteristics != NULL)
	{
		dwImprotCount++;
		printf("ImprotName:%s\n", imageBase + RvatoFoa(imageBase, hTempImport->Name));
		hTempImport = PIMAGE_IMPORT_DESCRIPTOR((char*)hTempImport + sizeof(IMAGE_IMPORT_DESCRIPTOR));

	}
	printf("����%d�������\n", dwImprotCount);
	//�������һ����,�Ե�ǰ�ļ�������������� ��������Ĵ�С+importdescriptor�����޸�section_handle.sizeofRawData.
	DWORD dwAlignment = hnt->OptionalHeader.FileAlignment;
	DWORD dwExpandSize = dwAlignment * ((dwImprotCount + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) / dwAlignment + 1) + 0x500;
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(hnt);
	PIMAGE_SECTION_HEADER pLastSection = &pFirstSection[hnt->FileHeader.NumberOfSections - 1];
	printf("LastSectionName:%s,dwExpandSize:%X\n", pLastSection->Name, dwExpandSize);
	pLastSection->SizeOfRawData += dwExpandSize;
	hnt->OptionalHeader.SizeOfImage += dwExpandSize;
	//������Ľڣ�����֮ǰ�ĵ�����,д���µĵ����,����һ��importdescriptor�Ĵ�С
	DWORD newbuffSize = fileSize + dwExpandSize;
	DWORD newImageBase = ExpandLastSection(imageBase, fileSize, dwExpandSize);
	DWORD lastBegin = (DWORD)newImageBase + fileSize;
	memcpy((PVOID)newImageBase, (PVOID)imageBase, fileSize);
	memcpy((PVOID)lastBegin, hImport, sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwImprotCount);
	/*�µĵ����λ��*/
	DWORD newImportRva = FoaToRva((DWORD)newImageBase, lastBegin - newImageBase);
	lastBegin += sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwImprotCount;
	//Ԥ��һ��������һ���յĵ����
	PVOID pAddrAddImport = (PVOID)lastBegin;
	lastBegin += sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;
	//�ڵ����ĺ�����д�ܶ�ṹ
	IMAGE_IMPORT_DESCRIPTOR AddImport = { 0 };
	IMAGE_THUNK_DATA thunkData = { 0 };
	PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)calloc(sizeof(IMAGE_IMPORT_BY_NAME) + strlen(szApiName) - 1, 1);
	importByName->Hint = 0;
	memcpy(importByName->Name, szApiName, strlen(szApiName) + 1);
	memcpy((PVOID)lastBegin, importByName, sizeof(IMAGE_IMPORT_BY_NAME) + strlen(szApiName) - 1);
	thunkData.u1.AddressOfData = FoaToRva((DWORD)newImageBase, lastBegin - (DWORD)newImageBase);
	lastBegin += sizeof(IMAGE_IMPORT_BY_NAME) + strlen(szApiName) - 1;
	memcpy((PVOID)lastBegin, &thunkData, sizeof(IMAGE_THUNK_DATA));
	lastBegin += sizeof(IMAGE_THUNK_DATA);
	/*��1��ֵ*/
	AddImport.OriginalFirstThunk = FoaToRva((DWORD)newImageBase, lastBegin - (DWORD)newImageBase);
	memcpy((PVOID)lastBegin, &thunkData, sizeof(IMAGE_THUNK_DATA));
	lastBegin += sizeof(IMAGE_THUNK_DATA) * 2;
	/*��2��ֵ*/
	AddImport.FirstThunk = FoaToRva((DWORD)newImageBase, lastBegin - (DWORD)newImageBase);
	memcpy((PVOID)lastBegin, &thunkData, sizeof(IMAGE_THUNK_DATA));
	lastBegin += sizeof(IMAGE_THUNK_DATA) * 2;
	/*Name1��ֵ*/
	memcpy((PVOID)lastBegin, szDllName, strlen(szDllName) + 1);
	AddImport.Name = FoaToRva((DWORD)newImageBase, lastBegin - (DWORD)newImageBase);
	/*�����ֵ*/
	memcpy(pAddrAddImport, &AddImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	//�޸�����Ŀ¼���е����ĵ�ַ
	PIMAGE_DOS_HEADER hNewdos = (PIMAGE_DOS_HEADER)newImageBase;
	PIMAGE_NT_HEADERS hNewNt = (PIMAGE_NT_HEADERS)(newImageBase + hNewdos->e_lfanew);
	hNewNt->OptionalHeader.DataDirectory[1].VirtualAddress = newImportRva;
	//д���ļ�
	OFSTRUCT of = { 0 };
	of.cBytes = sizeof(OFSTRUCT);
	HFILE hNewFile = OpenFile("C:\\Users\\admin\\Desktop\\newFile.exe", &of, OF_CREATE);
	DWORD dwNewfullSize = 0;
	WriteFile((HANDLE)hNewFile, (PVOID)newImageBase, newbuffSize, &dwNewfullSize, 0);

	//��ɨ
	free(importByName);
	free((PVOID)newImageBase);
	CloseHandle((HANDLE)hNewFile);
	return 0;
}
//����������
void EnumExport(DWORD dwImageBase) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER hOptional = pHeader->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwImageBase + RvatoFoa(dwImageBase, hOptional.DataDirectory[0].VirtualAddress));
	DWORD exportNumber = pExport->NumberOfFunctions;
	if (pExport->AddressOfNameOrdinals != 0) {
		WORD* indexVa = (WORD*)(RvatoFoa(dwImageBase, pExport->AddressOfNameOrdinals) + dwImageBase);
		int i = 0;
		while (exportNumber != 0)
		{
			WORD  index = *indexVa;
			DWORD* name = (DWORD*)(RvatoFoa(dwImageBase, pExport->AddressOfNames) + dwImageBase);
			char* funName = (char*)(RvatoFoa(dwImageBase, name[i]) + dwImageBase);
			DWORD* funAddr = (DWORD*)(RvatoFoa(dwImageBase, pExport->AddressOfFunctions) + dwImageBase);
			printf("�������:%d,������ַ:%x,����������:%s\n", index + pExport->Base, funAddr[index] + hOptional.ImageBase, funName);
			i++;
			indexVa++;
			exportNumber--;
		}
		return;
	}
	else if(pExport->AddressOfNames !=NULL) {
	
		PDWORD pNameTable = (PDWORD)(RvatoFoa(dwImageBase, pExport->AddressOfNames) + dwImageBase);
		int i = 0;
		while (i< pExport->NumberOfNames)
		{
			
			PDWORD pNameOA = (PDWORD)(RvatoFoa(dwImageBase, pNameTable[i]) + dwImageBase);
			printf("��������:%s\n", pNameOA);
			i++;
		}
	}
	
}
BOOL checkDllVersion(DWORD dwImageBase) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	if (pHeader->FileHeader.Machine == 0x8664) {
		printf("�ݲ�֧��64λdll��\n");
		return FALSE;
	}
	return TRUE;

}
//�����ļ� 
void SaveFile_PE(DWORD dwNewImageBase, DWORD fileSize) {

	OFSTRUCT of = { 0 };
	of.cBytes = sizeof(OFSTRUCT);
	HFILE hNewFile = OpenFile("C:\\Users\\admin\\Desktop\\newFile_Export.dll", &of, OF_CREATE);
	DWORD dwNewfullSize = 0;
	bool state = WriteFile((HANDLE)hNewFile, (PVOID)dwNewImageBase, fileSize, &dwNewfullSize, 0);
	if (state) {
		printf("�ļ�����ɹ�\n");
	}
	else
	{
		printf("�ļ�����ʧ�� Error:%d\n", GetLastError());
	}
	CloseHandle((HANDLE)hNewFile);
}
/*
����:��������(��),�ƶ���Ӧ���ļ�ָ��
����:(�Զ���)�ļ�ָ��
*/
DWORD CopyTable(DWORD targetAddr, DWORD origAddr, DWORD elementCount, DWORD elementSize) {
	char* dwPoint = (char*)targetAddr;
	while (elementCount != 0)
	{
		memcpy((PVOID)targetAddr, (PVOID)origAddr, elementSize);
		targetAddr += elementSize;
		origAddr += elementSize;
		dwPoint += elementSize;
		elementCount--;
	}

	return (DWORD)dwPoint;
}
//����˽�к���
BOOL ExportPrivateFunction(DWORD dwImageBase, DWORD fileSize, DWORD dwExportAddressRVA, char* szExpandName) {
	//��ȡ��������,����ԭ�ȵĵ����������Ʊ���ű���ַ��
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwImageBase + RvatoFoa(dwImageBase, pHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
	if (pExport->NumberOfFunctions != pExport->NumberOfNames) {
		printf("��֧������ŵ�����DLL\n");
		return FALSE;
	}
	DWORD exportCount = pExport->NumberOfFunctions;
	//�����µ����α��С
	DWORD dwExpandSize = (exportCount * (2 + 4 + 4) / pHeader->OptionalHeader.FileAlignment + 1) * pHeader->OptionalHeader.FileAlignment;
	//�������һ�����εĴ�С
	DWORD dwNewImageBase = ExpandLastSection(dwImageBase, fileSize, dwExpandSize);
	//�µ��ڴ�PE�ṹ
	PIMAGE_DOS_HEADER NewdosHeader = (PIMAGE_DOS_HEADER)dwNewImageBase;
	PIMAGE_NT_HEADERS pNewHeader = (PIMAGE_NT_HEADERS)(dwNewImageBase + NewdosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pNewExport = (PIMAGE_EXPORT_DIRECTORY)(dwNewImageBase + RvatoFoa(dwNewImageBase, pNewHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
	//�Զ�����ļ�ָ��
	DWORD lastPoint = dwNewImageBase + fileSize;

	//���Ƶ�����������
	memcpy((PVOID)lastPoint, szExpandName, strlen(szExpandName) + 1);
	DWORD ExportnamePoint = lastPoint;
	lastPoint += strlen(szExpandName) + 1;

	//ȡ�������ַ
	DWORD dwNameAddr = dwNewImageBase + RvatoFoa(dwNewImageBase, pNewExport->AddressOfNames);
	DWORD exprotFunctionArray = dwNewImageBase + RvatoFoa(dwNewImageBase, pNewExport->AddressOfFunctions);
	DWORD exprotOrdllalsArray = dwNewImageBase + RvatoFoa(dwNewImageBase, pNewExport->AddressOfNameOrdinals);

	//�������Ʊ�
	DWORD dwImportNameAddr = lastPoint;
	lastPoint = CopyTable(dwImportNameAddr, dwNameAddr, exportCount, 4);
	//д���µĵ�����������Rva
	*(DWORD*)lastPoint = FoaToRva(dwNewImageBase, ExportnamePoint - dwNewImageBase);
	lastPoint += 4;


	//������ַ��
	DWORD dwImportAddress = lastPoint;
	lastPoint = CopyTable(lastPoint, exprotFunctionArray, exportCount, 4);
	/*������������ַ������д�뵼��������ַrva*/
	*(DWORD*)lastPoint = dwExportAddressRVA;
	lastPoint += 4;

	//������ű�
	DWORD dwImportOrdllialAddr = lastPoint;
	lastPoint = CopyTable(lastPoint, exprotOrdllalsArray, exportCount, 2);
	/*�������������������д�뵼���������*/
	*(WORD*)lastPoint = exportCount;
	lastPoint += 2;


	//�޸ĵ�����ĵ�������������������ַ��ĵ�ַ
	pNewExport->NumberOfFunctions = exportCount + 1;
	pNewExport->NumberOfNames = exportCount + 1;
	pNewExport->AddressOfFunctions = FoaToRva(dwNewImageBase, dwImportAddress - dwNewImageBase);
	pNewExport->AddressOfNameOrdinals = FoaToRva(dwNewImageBase, dwImportOrdllialAddr - dwNewImageBase);
	pNewExport->AddressOfNames = FoaToRva(dwNewImageBase, dwImportNameAddr - dwNewImageBase);
	//�����ļ�
	SaveFile_PE(dwNewImageBase, fileSize + dwExpandSize);
	//��ɨ
	free((PVOID)dwNewImageBase);
}

//�����ض�λ��
BOOL EnumRelocationTable(DWORD dwImagebase) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImagebase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImagebase + dosHeader->e_lfanew);
	PIMAGE_BASE_RELOCATION pReloaction = (PIMAGE_BASE_RELOCATION)(dwImagebase + RvatoFoa(dwImagebase, pHeader->OptionalHeader.DataDirectory[5].VirtualAddress));
	while (pReloaction->VirtualAddress!=0)
	{
		printf("�ض�λ�ڴ�ҳRVA��ַ:%X,��Ҫ�ض�λ��RVA��ַ,����:\n", pReloaction->VirtualAddress);
		DWORD dwRelocationCount = (pReloaction->SizeOfBlock - 8) / 2;
		UWORD* pBlock = (UWORD*)((char*)pReloaction + 8);
		int i = 0, j = 0;;
		while (dwRelocationCount!=0)
		{
			if ((pBlock[j] & 0xF000)>>12==3) {
				printf("\t%x", pBlock[j]&0xFFF);
				i++;
				if (i == 5) {
					printf("\n");
					i = 0;
				}		
		}
		
			j++;
			dwRelocationCount--;
		}
		printf("\n");
		pReloaction = (PIMAGE_BASE_RELOCATION)(((char*)pReloaction) + pReloaction->SizeOfBlock);
		
	}
	return 1;
}
//��ȡ�ӳٵ������Ϣ
void GetDelayImportTableInfomation(DWORD dwImageBase) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayLoad = (PIMAGE_DELAYLOAD_DESCRIPTOR)(dwImageBase+ RvatoFoa(dwImageBase, pHeader->OptionalHeader.DataDirectory[13].VirtualAddress));
	while (pDelayLoad->DllNameRVA!=0)
	{	
		printf("\nDelayImportName:%s\n", dwImageBase + RvatoFoa(dwImageBase, pDelayLoad->DllNameRVA));
		PIMAGE_THUNK_DATA  INTThunk =	(PIMAGE_THUNK_DATA)(dwImageBase +RvatoFoa(dwImageBase, pDelayLoad->ImportNameTableRVA));
		pDelayLoad++;
		int i = 0;
		while (INTThunk->u1.AddressOfData!=0)
		{	
			if ((INTThunk->u1.AddressOfData & 0x80000000) == 0x80000000) {
				printf("\t%d", INTThunk->u1.AddressOfData&0x7fffffff);

			}
			else {
				PIMAGE_IMPORT_BY_NAME pImprotName = (PIMAGE_IMPORT_BY_NAME)(dwImageBase + RvatoFoa(dwImageBase, INTThunk->u1.AddressOfData));
				printf("\t%s",pImprotName->Name);
			}
			INTThunk++;
			i++;
			if (i==5) {
				i = 0;
				printf("\n");
			}
		}
		
		
	
	}

}
//����ntdll ���ú�
long ParsePE(char* functionName,DWORD readBuffer,DWORD dwNumber) {
	if (readBuffer == NULL) {
		return 0 ;
	}
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)readBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(readBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != 0x4550) {
		printf("PE��ȡʧ��\n");
		return -1;
	}
	PIMAGE_OPTIONAL_HEADER optionHeader = &(ntHeaders->OptionalHeader);
	PIMAGE_DATA_DIRECTORY importTable = &(optionHeader->DataDirectory[0]);
	PIMAGE_EXPORT_DIRECTORY pimportTable;
	pimportTable = (PIMAGE_EXPORT_DIRECTORY)(readBuffer + RvatoFoa(readBuffer,importTable->VirtualAddress));
	char* DllName = (char*)RvatoFoa(readBuffer,pimportTable->Name) + readBuffer;
	PULONG functionAddr = (PULONG)(RvatoFoa(readBuffer, pimportTable->AddressOfFunctions) + readBuffer);
	PULONG NameTableAddr = (PULONG)(RvatoFoa(readBuffer, pimportTable->AddressOfNames) + readBuffer);
	USHORT* OrdinalsTableAddr = (USHORT*)(RvatoFoa(readBuffer, pimportTable->AddressOfNameOrdinals) + readBuffer);
	for (int i = 0; i < pimportTable->NumberOfNames; i++)
	{
		char* dllfunctionName = (char*)(RvatoFoa(readBuffer, NameTableAddr[i]) + readBuffer);

			
			//��ȡ��ű�
			short index = OrdinalsTableAddr[i];
			unsigned char* finalfunctionAddr = (unsigned char*)(RvatoFoa(readBuffer, functionAddr[index]) + readBuffer);
			if (*finalfunctionAddr == 0x8b) {

				continue;
			}
			long tasknumber = 0;
			_asm {
				push eax;
				xor eax, eax;
				mov  eax, finalfunctionAddr;
				inc eax;
				mov eax, [eax];
				mov tasknumber, eax;
				pop eax;
			}
			if (dwNumber == 0&& functionName==NULL) {
				printf("������:%s �����:%x\n", dllfunctionName, tasknumber);
			}else if(dwNumber != 0&&dwNumber == tasknumber) {
				printf("������:%s �����:%x\n", dllfunctionName, tasknumber);
				break;
			}
			else if(functionName != NULL &&strcmp(functionName, dllfunctionName)==0)
			{
				printf("������:%s �����:%x\n", dllfunctionName, tasknumber);
				break;
			}
		

	}
	
	return NULL;
}
// Tls
void TlsTools(DWORD dwImageBase) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	PIMAGE_TLS_DIRECTORY32 pTlsDirectory = (PIMAGE_TLS_DIRECTORY32)(dwImageBase + RvatoFoa(dwImageBase, pHeader->OptionalHeader.DataDirectory[9].VirtualAddress));
	ULONG* dwCallBackAddr =(PULONG)(dwImageBase + RvatoFoa(dwImageBase, pTlsDirectory->AddressOfCallBacks - pHeader->OptionalHeader.ImageBase));
	int i = 0;
	while (dwCallBackAddr[i]!=0)
	{
		printf("dwCallBackVA:%x\n", dwCallBackAddr[i]);
		i++;
	}
	
}
//SEH����
void EnumSEH(DWORD dwImageBase) {

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	PIMAGE_LOAD_CONFIG_DIRECTORY pSEH = (PIMAGE_LOAD_CONFIG_DIRECTORY)(dwImageBase + RvatoFoa(dwImageBase, pHeader->OptionalHeader.DataDirectory[10].VirtualAddress));
	DWORD dwSEHCount = pSEH->SEHandlerCount;
	int i = 0;
	while (dwSEHCount!=0)
	{
		PDWORD pSEHArray = (PDWORD)(dwImageBase + RvatoFoa(dwImageBase, pSEH->SEHandlerTable - pHeader->OptionalHeader.ImageBase));
		printf("SEHandler RVA:%p\n", pSEHArray[i]);
		i++;
		dwSEHCount--;
	}
}

void _declspec(naked)asmPE() {
	//6B 65 72 6E  65 6C 33 32  2E 64 6C 6C			kernel32.dll
	_asm {
		//����ַ��� ��push�ַ���ĩβ 
		//75 73 65 72  33 32 2E 64  6C 6C				user32.dll
		mov esi, esp;
		push 0;
		push 0x006c006c;
		push 0x0064002e;
		push 0x00320033;
		push 0x00720065;
		push 0x00730075;	//ebx+0x64
		//4C 6F 61 64 4C 69 62 72 61 72 79 41			LoadLibraryA
		push 0;
		push 0x41797261;
		push 0x7262694c;
		push 0x64616f4c;	//ebx+0x54			LoadLibraryA

		//48 65 6C 6C  6F 20 35 31  68 6F 6F 6B			Hello 51hook
		push 0x0;
		push 0x6b6f6f68;
		push 0x3135206f;
		push 0x6c6c6548;	//ebx+0x44			hello 51hokk

		//4D 65 73 73  61 67 65 42  6F 78 41			MessageBoxA
		push 0x41786f;
		push 0x42656761;
		push 0x7373654d;		//ebx+0x38			messageboxa

		//75 73 65 72  33 32 2E 64  6C 6C				user32.dll
		push 0x6c6c;
		push 0x642e3233;
		push 0x72657375;		//ebx+0x2C			user32.dll


		//47 65 74 50  72 6F 63 41  64 64 72 65  73 73  GetProcAddress
		push 0x7373;
		push 0x65726464;
		push 0x41636f72;
		push 0x50746547;		//ebx+0x1c	GetProcAddress


		push 0x0;
		push 0x004c004c;
		push 0x0044002e;
		push 0x00320033;
		push 0x004c0045;
		push 0x004e0052;
		push 0x0045004b;	//ebx		kernel32.dll ��д
	//��ʱ��esp�����ַ������׵�ַ ��ebx ����ַ���ָ�� ����ĵ�ַ;
		mov ebx, esp;
		call PalyLoad;
		mov esp, esi;
		ret;

		//ebx ����ַ���������׵�ַ




		//��ȡ�ַ������� �� ecx��¼  MyGetStrLen(const char* str)  eax �����ַ�������
		// 
		//���� :������
		//����:��ȡ�������ַ�������
		//����ֵ:eax ���溯�����ַ�������
	MyGetStrLen:
		push ebp;
		mov ebp, esp;
		sub esp, 0x20;



		mov eax, dword ptr ds : [ebp + 0x8] ;
		xor ecx, ecx;
	FLAG:
		cmp word ptr ds : [eax] , 0;
		je EXIT;
		inc cx;
		add eax, 0x2;
		jmp FLAG;
	EXIT:
		mov eax, ecx

			//eax�Ƿ���ֵ
			mov esp, ebp;
		pop ebp;
		ret 0x4;

		//MyGetDllBase(const char* str)     ����:������ 
		//									����:��ȡ��Ӧ�ĺ������� imagebase 
	MyGetDllBase:
		push ebp;
		mov ebp, esp;
		sub esp, 0x20;

		push esi // str
			push edi; // dllName
		push edx;// ��ַ
		push ebx;
		push ecx;


		mov ebx, [ebp + 0x8];			 //���������� ��ֵ�� ebx
		push ebx;
		call MyGetStrLen;
		mov ecx, eax						//����ѭ������ == dllname �ַ����ĳ���
		mov esi, dword ptr fs : [0x30] ;				//��ȡ ��Ӧdll�� image base
		mov esi, [esi + 0xc];
		mov esi, [esi + 0x1c];				//��ó��������dll������׵�ַ
	MyGetDllBaseLoop:

		mov edx, esi;
		mov esi, [esi + 0x20];              //��õ�ǰdll������ ��ַ  unicode����
		mov edi, ebx
		REPE CMPSW;
		JECXZ MyGetDllBaseExit;
		mov ecx, eax;
		mov esi, [edx];
		jmp MyGetDllBaseLoop;

	MyGetDllBaseExit:
		mov eax, [edx + 0x8];				//eax����dllbase

		pop ecx;
		pop ebx;
		pop edx;
		pop edi;
		pop esi;

		mov esp, ebp;
		pop ebp;
		ret 0x4;
		//ͨ��dllbase �ҵ� �����ĵ�ַ  MyGetFunAddr(const char * funname ,constr char * dllname ,int strlen )

	MyGetFunAddr:
		push ebp;
		mov ebp, esp;
		sub esp, 0x20;

		push ebx;
		push esi;
		push edi;
		push ebp;
		push edx;

		push[ebp + 0xC];			//����dllname��ַ
		call MyGetDllBase;
		//��ʱeax ��dllBase
		mov esi, [eax + 0x3c];  //esi = e_ifanew 
		lea esi, [eax + esi];   //NTͷ ��ַ
		mov esi, [esi + 0x78];  //�������rva��ַ
		lea esi, [eax + esi];		//�������va��ַ

		mov edi, [esi + 0x1c];    //EAT RVA  ������ַ��
		lea edi, [eax + edi];	//EAT VA
		mov[ebp - 0x4], edi;	 //�����һ���ֲ�����

		mov edi, [esi + 0x20];	//ENT RVA  �������Ƶ�ַ��
		lea edi, [eax + edi];	//ENT VA 
		mov[ebp - 0x8], edi;

		mov edi, [esi + 0x24];	//EOT RVA  ����������ű�
		lea edi, [eax + edi];	//EOT VA 
		mov[ebp - 0xc], edi;
		cld;
		xor edx, edx;
		//�ѻ�����ű�  ��ʼ�ȽϷ�������
	MyGetFunAddrExitLoop:
		mov ecx, [ebp + 0x10]; //	����ĵ��������� �ַ�������
		mov esi, [ebp - 0x8];
		mov esi, [esi + 4 * edx];
		lea esi, [eax + esi];		//�������Ƶĵ�ַ
		mov edi, [ebp + 0x8]		//����ĵ�һ������  �ַ����ĵ�ַ
			repe cmpsb;
		jecxz MyGetFunAddrGetEOT;
		inc edx;
		jmp MyGetFunAddrExitLoop;
	MyGetFunAddrGetEOT:
		xor ebx, ebx;
		mov esi, [ebp - 0xc];
		mov bx, [esi + edx * 2]; //EAT�������

		mov edi, [ebp - 0x4];
		mov edi, [edi + ebx * 4];  //edi���Ǻ�����RVA��ַ
		lea eax, [eax + edi];		//���� eax  �� ������RVA��ַ

	MyGetFunAddrExit:
		/*
		push ebx;
		push esi;
		push edi;
		push ebp;
		push eax;
		*/

		pop edx;
		pop ebp;
		pop edi;
		pop esi;
		pop ebx;

		mov esp, ebp;
		pop ebp;
		ret 0x10;

	PalyLoad:
		push ebp;
		mov ebp, esp;
		sub esp, 0x20;


		// MyGetFunAddr(const char * funname ,constr char * dllname ,int funnameStrlen )

		push 0xc;
		push ebx;
		lea edi, [ebx + 0x54];	//LoadLibraryA�������ĵ�ַ
		push edi;
		call MyGetFunAddr;  //��ʱeax���� LoadLibraryA �����ĵ�ַ
		mov[ebp - 0x8], eax	//LoadLibraryA�ĵ�ַ


		//����LoadLibraryA
			lea edi, [ebx + 0x2C]  //user32.dll ascll �ַ����ĵ�ַ
			push edi;
		call[ebp - 0x8];

		//��ȡGetProcAddr��ַ
		push 0xb;
		push ebx;
		lea edi, [ebx + 0x1c];
		push edi;
		call MyGetFunAddr;  //��ʱeax���� GetProcAddr �����ĵ�ַ
		mov[ebp - 0x4], eax;  //GetProcAddress�ĵ�ַ

		//��ȡ user32 base
		lea edi, [ebx + 0x64];	//��tm�� user32.dll �� unicode Сд
		push edi;				//���� user32.dll unicode �ַ����ĵ�ַ
		call MyGetDllBase
			//��ʱ��eax �� user32.dll ��hModule

			//����GetProcAddress (dllbase,funname)
			lea edi, [ebx + 0x38];
		push edi;
		push eax;
		call[ebp - 0x4];
		//��ʱ eax ���� MessageBoxA�ĵ�ַ;

		lea ecx, [ebx + 0x44];
		push 0;
		push 0;
		push ecx;
		push 0;
		call eax;

		mov esp, ebp;
		pop ebp;
		ret;
	}

}

/*
��ȡDLL��ַ
*/
DWORD GetModuleBase(DWORD pPEB, WCHAR* szModuleName) {
	pPEB += 0xc;
	PPEB_LDR_DATA pLDR = (PPEB_LDR_DATA) * (PDWORD)pPEB;
	PLIST_ENTRY initList = pLDR->InLoadOrderModuleList.Flink;
	DWORD dwModuleImageBase = 0;
	PLDR_DATA_TABLE_ENTRY pDataTable = NULL;
	do
	{
		pDataTable = (PLDR_DATA_TABLE_ENTRY)initList;
		//����ͷ�˳�
		if (pDataTable->DllBase == 0) {
			printf("δ��ָ��ģ��\n");
			break;
		}
		if (lstrcmpW(szModuleName, pDataTable->BaseDllName.Buffer) == 0) {
		
			dwModuleImageBase = (DWORD)pDataTable->DllBase;
			printf("ModuleName:%ws\n", pDataTable->BaseDllName.Buffer);
			break;
		
		}
		initList = initList->Flink;
	} while (initList->Flink != pLDR->InLoadOrderModuleList.Flink->Flink);
	return dwModuleImageBase;
}
/*
	�ڴ�PE,ƥ�䵼�����Ʊ�
*/
DWORD SearchModuleExportTable(DWORD dwImageBase, char* szFunctionName) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pHeader = (PIMAGE_NT_HEADERS)(dwImageBase + dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER hOptional = pHeader->OptionalHeader;
	if (hOptional.DataDirectory[0].VirtualAddress==0) {
		printf("δ�ҵ����Ƶ�����\n");
		return 0;
	}
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(hOptional.DataDirectory[0].VirtualAddress + dwImageBase);
	DWORD i = 0;
	DWORD index = -1;
	while (i< pExport->NumberOfNames)
	{
		PDWORD pNameTable = (PDWORD)(pExport->AddressOfNames + dwImageBase);
		char* pFunctionName = (char*)(pNameTable[i] + dwImageBase);
		
		if (strcmp(szFunctionName, pFunctionName) == 0) {
			printf("FunctionName:%s\n", pFunctionName);
			index = i;
			break;
		}
		i++;
	}
	if (index==-1) {
		printf("δ��̬��λ������\n");
		return 0;
	}
	//�ҵ�ʣ�µ�������
	PDWORD pExprotFunctionArray =(PDWORD)(dwImageBase + pExport->AddressOfFunctions);
	PWORD pExprotOrdllalsArray =(PWORD)(dwImageBase + pExport->AddressOfNameOrdinals);
	DWORD funAddr = pExprotFunctionArray[pExprotOrdllalsArray[index]];

	printf("Function Address :%p\n", funAddr+ dwImageBase);


	return  funAddr + dwImageBase;
}

DWORD GetFunctionAddr32(DWORD pPEB, WCHAR* szModuleName,char* szFunctionName) {

	DWORD dwImageBase =  GetModuleBase(pPEB, szModuleName);
	if (dwImageBase==0) {
		return 0;
	}
	char string[] = "hello word";
	printf("ModuleBase:%x\n", dwImageBase);
	DWORD dwFindFunctionAddr =  SearchModuleExportTable(dwImageBase, szFunctionName);
	if (dwFindFunctionAddr != 0) {
		_asm {
			lea eax, string;
			push eax;
			call dwFindFunctionAddr;
			
		}
	}
	return 0;
}
//ѹ��PE�ļ�
void CompressPE(DWORD dwImageBase,DWORD dwImageSize) {

	DWORD* pArray = (DWORD*)calloc(0x100, 4);
	int i = 0;
	UCHAR* nowPoint = (UCHAR*)dwImageBase;
	while (i<= dwImageSize)
	{
		pArray[*nowPoint] += 1;
		if (pArray[*nowPoint] == 0xFFFFFFFF) {
			printf("����Խ�� I=%d\n", *nowPoint);
		}
		nowPoint++;
		i++;
	}
	DWORD MaxHex = pArray[0];
	UCHAR ucMin = 0;
	for (size_t i = 0; i < 100; i++)
	{
		if (pArray[i]>0xa0) {
			printf("Hex:%x,Number:%d\n", i, pArray[i]);

		}
	}
	
}



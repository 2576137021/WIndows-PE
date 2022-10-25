#pragma once
#include <windows.h>
#include <imagehlp.h>
#include <iostream>
#pragma comment(lib, "ImageHlp.Lib")
BOOL EnumRelocationTable(DWORD dwImagebase);
BOOL ExportPrivateFunction(DWORD dwImageBase, DWORD fileSize, DWORD dwExportAddressRVA, char* szExpandName);
/*
ʹ�õ��Ľṹ��
*/

//
// Loader Data Table. Used to track DLLs loaded into an
// image.
//
typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            PVOID LoadedImports;
        };
    };
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;

    PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
/*
����:��������(��),�ƶ���Ӧ���ļ�ָ��
����:(�Զ���)�ļ�ָ��
*/
DWORD CopyTable(DWORD targetAddr, DWORD origAddr, DWORD elementCount, DWORD elementSize);
//�����ļ� 
void SaveFile_PE(DWORD dwNewImageBase, DWORD fileSize);
BOOL checkDllVersion(DWORD dwImageBase);
//����������
void EnumExport(DWORD dwImageBase);
//�޸ĵ����
BOOL ModifiImprot(char* szFileName, char* szDllName, char* szApiName);
/*
�������һ����, �����޸����һ����Ϊ�ɶ���д����
�޸�optionHandle�е����һ���ڱ�Ĵ�С��
����:�����ĵ�ַָ��
*/
DWORD ExpandLastSection(DWORD dwImageBase, DWORD fileSize, DWORD dwExpandSize);
DWORD FoaToRva(DWORD imagebase, DWORD foa);
DWORD32 GetIATAddr(DWORD32 dwImageBase);
void improtTable(DWORD dwImageBase, int dwFlag);
DWORD CalcCheckSum(DWORD imagebase, DWORD dwFileSize);
DWORD RvatoFoa(DWORD imagebase, DWORD rva);
DWORD OpenFile_PE(DWORD* dwRetFileSize, char* szFilePath);
int Pedump();
void printfLine(char* buffer, int lineNumber, int remainder);
//��ȡ�ӳٵ�������Ϣ
void GetDelayImportTableInfomation(DWORD dwImageBase);
//���nt���ú�
long ParsePE(char* functionName, DWORD readBuffer, DWORD dwNumber);
//tls
void TlsTools(DWORD dwImageBase);
//SEH
void EnumSEH(DWORD dwImageBase);
//��ද̬��ȡ������ַ
void asmPE();
//�����ȡ������ַ
DWORD GetFunctionAddr32(DWORD pPEB, WCHAR* szModuleName, char* szFunctionName);
//ѹ��PE�ļ�
void CompressPE(DWORD dwImageBase, DWORD dwImageSize);
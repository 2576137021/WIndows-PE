#pragma once
#include <windows.h>
#include <imagehlp.h>
#include <iostream>
#pragma comment(lib, "ImageHlp.Lib")
BOOL EnumRelocationTable(DWORD dwImagebase);
BOOL ExportPrivateFunction(DWORD dwImageBase, DWORD fileSize, DWORD dwExportAddressRVA, char* szExpandName);
/*
使用到的结构体
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
功能:复制数组(表),移动相应的文件指针
返回:(自定义)文件指针
*/
DWORD CopyTable(DWORD targetAddr, DWORD origAddr, DWORD elementCount, DWORD elementSize);
//保存文件 
void SaveFile_PE(DWORD dwNewImageBase, DWORD fileSize);
BOOL checkDllVersion(DWORD dwImageBase);
//遍历导出表
void EnumExport(DWORD dwImageBase);
//修改导入表
BOOL ModifiImprot(char* szFileName, char* szDllName, char* szApiName);
/*
扩大最后一个节, 并且修改最后一个段为可读可写属性
修改optionHandle中的最后一个节表的大小。
返回:扩大后的地址指针
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
//获取延迟导入表的信息
void GetDelayImportTableInfomation(DWORD dwImageBase);
//输出nt调用号
long ParsePE(char* functionName, DWORD readBuffer, DWORD dwNumber);
//tls
void TlsTools(DWORD dwImageBase);
//SEH
void EnumSEH(DWORD dwImageBase);
//汇编动态获取方法地址
void asmPE();
//代码获取方法地址
DWORD GetFunctionAddr32(DWORD pPEB, WCHAR* szModuleName, char* szFunctionName);
//压缩PE文件
void CompressPE(DWORD dwImageBase, DWORD dwImageSize);
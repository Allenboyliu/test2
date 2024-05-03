#include <ntifs.h>
#include <ntimage.h>
#include <windef.h>
#include"injectshell.h"
#include"Mmsearch.h"
#define DELAY_ONE_MICRSECOND (-10)
#define  DELAY_ONE_MILLISECOND (1000 * DELAY_ONE_MICRSECOND)

VOID MySleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}
#define DLL_PATH  L"C:\\hid66.dll" //L"C:\\SSJJ2.vmp.dll"

NTKERNELAPI
CHAR* PsGetProcessImageFileName(__in PEPROCESS Process);


NTKERNELAPI
PVOID
NTAPI
PsGetThreadTeb(IN PETHREAD Thread);

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
	PRKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment,
}KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
	IN PKAPC Apc,
	IN PKTHREAD Thread,
	IN KAPC_ENVIRONMENT ApcStateIndex,
	IN PKKERNEL_ROUTINE KerenelRoutine,
	IN PKRUNDOWN_ROUTINE RundownRoutine,
	IN PKNORMAL_ROUTINE NormalRoutine,
	IN KPROCESSOR_MODE ApcMode,
	IN PVOID NormalContexe
);

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
PKAPC Apc,
PVOID SystemArgument1,
PVOID SystemArgument2,
KPRIORITY Increment
);

/*typedef DWORD(WINAPI *PfnZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateThreadFlags,
    DWORD  ZeroBits,
    DWORD  StackSize,
    DWORD  MaximumStackSize,
    LPVOID pUnkown);*/
typedef NTSTATUS(NTAPI* fn_NtCreateThreadEx)
(
	OUT PHANDLE hTread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);
fn_NtCreateThreadEx NtCreateThreadEx;

//	status = NtCreateThreadEx(&hthread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), pr3shellbuffer, pr3filebuffer, 0, 0, 0x10000, 0x20000, NULL);
		

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID       ServiceTableBase;
	PVOID       ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID       ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

BYTE  InJectDllx64[] =
{
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0x83, 0xec, 0x28,
	0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0x31, 0xd2,
	0x48, 0x31, 0xc9,
	0xff, 0xd0,
	0x48, 0x83, 0xc4, 0x28,
	0xc3
};


BOOLEAN   bacpinsert = FALSE;
KEVENT    apcenvent = { 0 };

ULONG GetIndexByName(UCHAR* sdName)
{
	NTSTATUS Status;
	HANDLE FileHandle;
	IO_STATUS_BLOCK ioStatus;
	FILE_STANDARD_INFORMATION FileInformation;
	//设置NTDLL路径
	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntdll.dll");

	//初始化打开文件的属性
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &uniFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	//创建文件

	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes,
		&ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
		return 0;
	//获取文件信息

	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation,
		sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status)) {
		ZwClose(FileHandle);
		return 0;
	}
	//判断文件大小是否过大
	if (FileInformation.EndOfFile.HighPart != 0) {
		ZwClose(FileHandle);
		return 0;
	}
	//取文件大小
	ULONG uFileSize = FileInformation.EndOfFile.LowPart;


	//分配内存
	PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, (ULONG64)uFileSize + 0x100, 0);
	if (pBuffer == NULL) {
		ZwClose(FileHandle);
		return 0;
	}

	//从头开始读取文件
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status)) {
		ZwClose(FileHandle);
		return 0;
	}
	//取出导出表
	PIMAGE_DOS_HEADER  pDosHeader;
	PIMAGE_NT_HEADERS  pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	ULONGLONG     FileOffset;//这里是64位数的，所以这里不是32个字节
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	//DLL内存数据转成DOS头结构
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	//取出PE头结构
	pNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)pBuffer + pDosHeader->e_lfanew);
	//判断PE头导出表表是否为空


	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return 0;

	//取出导出表偏移
	FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//取出节头结构
	pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;
	//遍历节结构进行地址运算
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= (ULONG64)(pSectionHeader->VirtualAddress) + (ULONG64)(pSectionHeader->SizeOfRawData))
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}

	//导出表地址
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pBuffer + FileOffset);
	//取出导出表函数地址
	PULONG AddressOfFunctions;
	FileOffset = pExportDirectory->AddressOfFunctions;
	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= (ULONG64)(pSectionHeader->VirtualAddress) + (ULONG64)(pSectionHeader->SizeOfRawData))
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfFunctions = (PULONG)((ULONGLONG)pBuffer + FileOffset);//这里注意一下foa和rva

	//取出导出表函数名字
	PUSHORT AddressOfNameOrdinals;
	FileOffset = pExportDirectory->AddressOfNameOrdinals;

	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= (ULONG64)(pSectionHeader->VirtualAddress) + (ULONG64)(pSectionHeader->SizeOfRawData))
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfNameOrdinals = (PUSHORT)((ULONGLONG)pBuffer + FileOffset);//注意一下foa和rva

	//取出导出表函数序号
	PULONG AddressOfNames;
	FileOffset = pExportDirectory->AddressOfNames;

	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= (ULONG64)(pSectionHeader->VirtualAddress) + (ULONG64)(pSectionHeader->SizeOfRawData))
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfNames = (PULONG)((ULONGLONG)pBuffer + FileOffset);//注意一下foa和rva


	//分析导出表
	ULONG uNameOffset = 0;
	ULONG uOffset = 0;
	LPSTR FunName;
	PVOID pFuncAddr;
	ULONG uServerIndex;
	ULONG uAddressOfNames;
	for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++) {
		uAddressOfNames = *AddressOfNames;
		pSectionHeader = pOldSectionHeader;
		for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
			if (pSectionHeader->VirtualAddress <= uAddressOfNames && uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
				uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
		FunName = (LPSTR)((ULONGLONG)pBuffer + uOffset);
		if (FunName[0] == 'Z' && FunName[1] == 'w') {
			pSectionHeader = pOldSectionHeader;
			uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
			for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++) {
				if (pSectionHeader->VirtualAddress <= uOffset && uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
					uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			}
			pFuncAddr = (PVOID)((ULONGLONG)pBuffer + uNameOffset);
			uServerIndex = *(PULONG)((ULONGLONG)pFuncAddr + 4);
			FunName[0] = 'N';
			FunName[1] = 't';
			if (!_stricmp(FunName, (const char*)sdName)) {//获得指定的编号
				ExFreePoolWithTag(pBuffer, 0);
				ZwClose(FileHandle);
				return uServerIndex;
			}
		}
	}

	ExFreePoolWithTag(pBuffer, 0);
	ZwClose(FileHandle);
	return 0;
}

ULONGLONG GetSSDTFuncCurAddr(ULONG id)
{
	ULONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[id];
	dwtmp = dwtmp >> 4;
	return (ULONG64)dwtmp + (ULONG64)ServiceTableBase;//需要先右移4位之后加上基地址，就可以得到ssdt的地址
}
int dv_SearchMem(char* memSourc, int memSize, char* searchdata, int len, int searchstart, BOOLEAN reversesearch)
{
	int dataindex = -1;
	if (memSourc == NULL || memSize <= len || len <= 0 || searchstart < 0)
	{
		return dataindex;
	}
	char* startp = memSourc + searchstart;
	char* endp = memSourc + memSize - len;

	char* curp = startp;
	while (curp >= memSourc && curp <= endp)
	{
		if (memcmp(curp, searchdata, len) == 0)
		{
			dataindex = (int)(curp - memSourc);
			break;
		}
		if (reversesearch)
			curp = curp - 1;
		else
			curp = curp + 1;
	}
	return dataindex;
}

ULONGLONG GetKeServiceDescriptorTable64_2()
{
	char KiSystemServiceStart_pattern[] = "\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00";    //特征码
	PUCHAR StartSearchAddress = (PUCHAR)ZwClose;
	PUCHAR CodeScanStart = (PUCHAR)NtClose;
	int  searchsize = (int)(CodeScanStart - StartSearchAddress);
	PUCHAR ssdtaddr = 0, memaddr = 0;
	//dv_SearchMem功能就是从StartSearchAddress开始搜索searchsize大小的内存块有没有KiSystemServiceStart_pattern特征,有就返回特征所在偏移
	int of = dv_SearchMem((char*)StartSearchAddress, searchsize, KiSystemServiceStart_pattern, sizeof(KiSystemServiceStart_pattern) - 1, 0, FALSE);
	if (of > 0)
	{
		of = dv_SearchMem((char*)StartSearchAddress, searchsize, "\x4C\x8D\x15", 3, of, FALSE);
		if (of > 0)
		{
			memaddr = StartSearchAddress + of;
			ssdtaddr = memaddr + 7 + ((*(LONG*)(memaddr + 3)));
		}
	}
	return (ULONGLONG)ssdtaddr;
}

ULONGLONG GetKeServiceDescriptorTable64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15) //4c8d15
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}


DWORD    AsdlookupProcessByName(PCHAR aprocessname)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS tempep = NULL;
	DWORD     dret = 0;
	PCHAR     processname = NULL;

	for (dret = 4; dret < 16777215; dret = dret + 4)
	{
		status = PsLookupProcessByProcessId((HANDLE)dret, &tempep);
		if (NT_SUCCESS(status))
		{
			ObDereferenceObject(tempep);
			processname = PsGetProcessImageFileName(tempep);
			if (MmIsAddressValid(processname))
			{
				if (strstr(processname, aprocessname))
				{
					break;
				}
			}
		}

	}
	return dret;
}

PVOID    AsdReadFiletoKernelMM(PWCHAR filepath, PSIZE_T outsize)
{
	HANDLE  hfile = NULL;
	UNICODE_STRING  unicodepath = { 0 };
	OBJECT_ATTRIBUTES  oba = { 0 };
	IO_STATUS_BLOCK  iosb = { 0 };
	PVOID  pret = NULL;
	NTSTATUS  status = STATUS_UNSUCCESSFUL;
	RtlInitUnicodeString(&unicodepath, filepath);
	InitializeObjectAttributes(&oba, &unicodepath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenFile(&hfile, GENERIC_ALL, &oba, &iosb, FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	FILE_STANDARD_INFORMATION fsi = { 0 };
	status = ZwQueryInformationFile(hfile, &iosb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hfile);
		return NULL;
	}
	pret = ExAllocatePool(PagedPool, (SIZE_T)fsi.EndOfFile.QuadPart);
	if (!(pret))
	{
		ZwClose(hfile);
		return NULL;
	}
	RtlZeroMemory(pret, (SIZE_T)fsi.EndOfFile.QuadPart);
	LARGE_INTEGER offset = { 0 };
	offset.QuadPart = 0;
	status = ZwReadFile(hfile, NULL, NULL, NULL, &iosb, pret, (LONG)fsi.EndOfFile.QuadPart, &offset, NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hfile);
		ExFreePool(pret);
		return NULL;
	}
	ZwClose(hfile);
	*outsize = fsi.EndOfFile.QuadPart;
	return pret;
}

BOOLEAN  AsdSkipApcThread(PETHREAD pThread)
{
	PUCHAR pTeb64 = NULL;
	pTeb64 = (PUCHAR)PsGetThreadTeb(pThread);
	
	if (!pTeb64)
		return TRUE;
	if (*(PULONG64)(pTeb64 + 0x78) != 0)
		return TRUE;

	if (*(PULONG64)(pTeb64 + 0x2c8) == 0)
		return TRUE;

	if (*(PULONG64)(pTeb64 + 0x58) == 0)
		return TRUE;

	return FALSE;
}

PETHREAD  AsdFindThreadInProcess(PEPROCESS tempep)
{
	PETHREAD  pretthreadojb = NULL, ptempthreadobj = NULL;
	PLIST_ENTRY  plisthead = NULL;
	PLIST_ENTRY  plistfink = NULL;
	INT          i = 0;
	plisthead = (PLIST_ENTRY)((PUCHAR)tempep + 0x30);
	plistfink = plisthead->Flink;
	for (plistfink; plistfink != plisthead; plistfink = plistfink->Flink)
	{
		ptempthreadobj = (PETHREAD)((PUCHAR)plistfink - 0x2f8);
		if (!MmIsAddressValid(ptempthreadobj))
			continue;
		i++;
		if (!AsdSkipApcThread(ptempthreadobj))
		{
			//__debugbreak();
			pretthreadojb = ptempthreadobj;
			break;
		}
	}
	return pretthreadojb;

}
VOID KernelAlertThreadApcEx(PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2) {


	return;
}
VOID KernelAlertThreadApc(PKAPC Apc, 
	PKNORMAL_ROUTINE* NormalRoutine, 
	PVOID* NormalContext, 
	PVOID* SystemArgument1, 
	PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	KeTestAlertThread(UserMode);
	DbgPrint("<asdiop>----KernelRoutine irql=%d\n", KeGetCurrentIrql());
	
	ExFreePool(Apc);
	return;
}

VOID KernelApcNormalRoutine(PVOID NormalContext, PVOID arg1, PVOID arg2)
{
	//DbgPrint("<asdiop>----KernelRoutine irql=%d\n", KeGetCurrentIrql());
	
	return;
}
 VOID apc_callback(
	PRKAPC Apc,
	PKNORMAL_ROUTINE * NormalRoutine,
	PVOID * NormalContext,
	PVOID * SystemArgument1,
	PVOID * SystemArgument2)
{
	ExFreePool(Apc);
}


VOID KernelInjectApc(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	if (PsIsThreadTerminating(PsGetCurrentThread()))
		*NormalRoutine = NULL;

	ExFreePool(Apc);

	bacpinsert = TRUE;

	KeSetEvent(&apcenvent, 0, FALSE);

	return;

}

VOID apc_callbackex(
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2)
{
	ExFreePool(Apc);
}

NTSTATUS AsdQueueUserApc(
	IN PETHREAD pthreadobj,
	IN PVOID puserapccall,
	IN PVOID apccontext,
	IN PVOID arg2,
	IN PVOID arg3,
	IN BOOLEAN bforce)
{
	PKAPC pforceapc = NULL;

	PKAPC pinjectapc = NULL;

	if (pthreadobj == NULL)
		return STATUS_INVALID_PARAMETER;

	pinjectapc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));

	RtlZeroMemory(pinjectapc, sizeof(KAPC));

	KeInitializeApc(
		pinjectapc,
		(PKTHREAD)pthreadobj,
		OriginalApcEnvironment,
		(PKKERNEL_ROUTINE)apc_callbackex,
		NULL,
		(PKNORMAL_ROUTINE)(ULONG_PTR)puserapccall,
		UserMode,
		apccontext);
	
	if (KeInsertQueueApc(pinjectapc, 0, 0, 0))
	{
		
		DbgPrintEx(77, 0, "成功\n");
	}
	
	return STATUS_SUCCESS;
}
//无线程shellcode注入

 

 ULONG64 调用exe函数Ex(HANDLE ProcessID,ULONG64 add) {
	 //char pname = "APC测试exe";
	 HANDLE  PID = 0;
	 PID = ProcessID;
	 ULONG64 pfunc = NULL;
	 pfunc = (ULONG64)0x1000000;

	 if ( PID > (HANDLE)100) {
		 for (size_t i = 4; i < 100000; i = i + 4)
		 {

			 PETHREAD pethread = NULL;
			 if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)i, &pethread)))
			 {

				 if (PsGetThreadProcessId(pethread) == PID)
				 {
					 if (*(LONGLONG*)((ULONG64)pethread + 0xC8) == 0) {
						 if (((*(ULONG*)((ULONG64)pethread + 0x74) >> 4) & 1) == 1) {

							 AsdQueueUserApc(pethread, add, 0, NULL, NULL, TRUE);
							 return;
						 }


					 }


				 }
				 ObDereferenceObject(pethread);

			 }




		 }



	 }


 }
VOID 调用exe函数(HANDLE ProcessID,ULONG64 地址666,ULONG64 rcx) {
	//char pname = "APC测试exe";
	HANDLE  PID = 0;
	PID = ProcessID;
	ULONG64 pfunc = NULL;
	pfunc = (ULONG64)地址666;

	if (pfunc > 10000 && PID > (HANDLE)100) {
		for (size_t i = 4; i < 100000; i = i + 4)
		{

			PETHREAD pethread = NULL;
			if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)i, &pethread)))
			{

				if (PsGetThreadProcessId(pethread) == PID)
				{
					if (*(LONGLONG*)((ULONG64)pethread + 0xC8) == 0) {
						if (((*(ULONG*)((ULONG64)pethread + 0x74) >> 4) & 1) == 1) {

							PRKAPC kapc = (PRKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
							KeInitializeApc(kapc, pethread, OriginalApcEnvironment, apc_callback, NULL, (PKNORMAL_ROUTINE)pfunc, UserMode, rcx);
							if (KeInsertQueueApc(kapc, 0, NULL, 0))
							{
								DbgPrintEx(77, 0, "已插入");
								return;
							}
						}


					}


				}
				ObDereferenceObject(pethread);

			}




		}



	}


}
NTSTATUS AsdKernelApcMapInject(DWORD pid, PVOID filebuffer, SIZE_T filesize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PEPROCESS tempep = NULL;

	KAPC_STATE  kapcs = { 0 };

	BOOLEAN battached = FALSE;

	PETHREAD apcthreadobj = NULL;

	PKAPC pkapcr = NULL;

	SIZE_T shellsize = 0, r3filesize = 0, r3imagesize = 0, ntimagesize = 0;

	PVOID pr3filebuffer = NULL, pr3shellbuffer = NULL, pr3imagebuffer = NULL;

	PIMAGE_DOS_HEADER pdos = NULL;

	PIMAGE_NT_HEADERS pnt = NULL;

	HANDLE hthread = NULL;

	PETHREAD pthreadobj = NULL;

	LARGE_INTEGER sleeptime = { 0 };
	do
	{
		status = PsLookupProcessByProcessId((HANDLE)pid, &tempep);
		if (!NT_SUCCESS(status))
			break;

		KeStackAttachProcess(tempep, &kapcs);

		battached = TRUE;

		apcthreadobj = AsdFindThreadInProcess(PsGetCurrentProcess());
		
		DbgPrintEx(77,0, "apcthreadobj%p\n", apcthreadobj);

		if (apcthreadobj == NULL)
		{
			break;
		}

		ObReferenceObject(apcthreadobj);

		pdos = (PIMAGE_DOS_HEADER)filebuffer;

		pnt = (PIMAGE_NT_HEADERS)((PUCHAR)filebuffer + pdos->e_lfanew);

		ntimagesize = pnt->OptionalHeader.SizeOfImage;

		r3imagesize = ntimagesize;

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3imagebuffer, 0, &r3imagesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(status))
			break;
		DbgPrint("<111>---\n");
		RtlZeroMemory(pr3imagebuffer, r3imagesize);

		r3filesize = filesize;
		//__debugbreak();
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3filebuffer, 0, &r3filesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status))
			break;
		DbgPrint("<222>---\n");
		RtlZeroMemory(pr3filebuffer, r3filesize);

		shellsize = sizeof(MmLoadShell_x64);

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3shellbuffer, 0, &shellsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(status))
			break;
		//__debugbreak();
		DbgPrint("<333>---\n");
		RtlZeroMemory(pr3shellbuffer, shellsize);

		RtlCopyMemory(pr3filebuffer, filebuffer, shellsize);

		*(PULONG_PTR)((PBYTE)MmLoadShell_x64 + 0x511) = (ULONG_PTR)pr3imagebuffer;
		RtlCopyMemory(pr3shellbuffer, MmLoadShell_x64, sizeof(MmLoadShell_x64));

		//KeInitializeEvent(&apcenvent, SynchronizationEvent, FALSE);
		
		sleeptime.QuadPart = -10000000 * 5;
		//__debugbreak();
		DbgPrintEx(77, 0, "pr3shellbuffer%p\n", pr3shellbuffer);
		status = AsdQueueUserApc(apcthreadobj, pr3shellbuffer, pr3filebuffer, NULL, NULL, TRUE);
		
		//KeWaitForSingleObject(&apcenvent, Executive, KernelMode, FALSE, &sleeptime);
		
		status = STATUS_SUCCESS;
		break;

	} while (1);
	if (battached)
	{
		if (!bacpinsert)
		{
			status = STATUS_UNSUCCESSFUL;
		}
		else
		{
		/*sleeptime.QuadPart = -10000000 * 3;
			KeDelayExecutionThread(KernelMode, 0, &sleeptime);
			if (pr3filebuffer)
			{
				RtlZeroMemory(pr3filebuffer, r3filesize);
				ZwFreeVirtualMemory(NtCurrentProcess(), &pr3filebuffer, &r3filesize, MEM_RELEASE);

			}
			if (pr3shellbuffer)
			{
				RtlZeroMemory(pr3shellbuffer, shellsize);
				ZwFreeVirtualMemory(NtCurrentProcess(), &pr3shellbuffer, &shellsize, MEM_RELEASE);

			}*/	

		}
		if (apcthreadobj)
		{
			ObDereferenceObject(apcthreadobj);
		}
		KeUnstackDetachProcess(&kapcs);

	}
	return status;
}
BOOLEAN MDLMoveMemory(PVOID pBaseAddress, PVOID pWriteData, SIZE_T writeDataSize)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	// 创建 MDL
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{
		return FALSE;
	}
	// 更新 MDL 对物理内存的描述
	MmBuildMdlForNonPagedPool(pMdl);
	// 映射到虚拟内存中
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
	}
	// 写入数据
	RtlCopyMemory(pNewAddress, pWriteData, writeDataSize);
	// 释放
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}
NTSTATUS AsdKernelApcMapInjectEx(DWORD pid, PVOID filebuffer, SIZE_T filesize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PEPROCESS tempep = NULL;

	KAPC_STATE  kapcs = { 0 };

	BOOLEAN battached = FALSE;

	PETHREAD apcthreadobj = NULL;

	PKAPC pkapcr = NULL;

	SIZE_T shellsize = 0, r3filesize = 0, r3imagesize = 0, ntimagesize = 0;

	PVOID pr3filebuffer = NULL, pr3shellbuffer = NULL, pr3imagebuffer = NULL;

	PIMAGE_DOS_HEADER pdos = NULL;

	PIMAGE_NT_HEADERS pnt = NULL;
	PVOID shell = 0;
	HANDLE hthread = NULL;

	PETHREAD pthreadobj = NULL;
	PVOID	ntdllbase11 = 0;
	LARGE_INTEGER sleeptime = { 0 };
	status = PsLookupProcessByProcessId((HANDLE)pid, &tempep);
	if (!NT_SUCCESS(status))
		return 1;
	PVOID	Read = 0;
	KeStackAttachProcess(tempep, &kapcs);
	PVOID	Create = 0;
	PVOID startaddresss555 = 0;

	__try {
		do
		{




			battached = TRUE;



			pdos = (PIMAGE_DOS_HEADER)filebuffer;

			pnt = (PIMAGE_NT_HEADERS)((PUCHAR)filebuffer + pdos->e_lfanew);

			ntimagesize = pnt->OptionalHeader.SizeOfImage;

			r3imagesize = ntimagesize;

			status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3imagebuffer, 0, &r3imagesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (!NT_SUCCESS(status))
				break;
			DbgPrint("<111>---\n");
			RtlZeroMemory(pr3imagebuffer, r3imagesize);

			r3filesize = filesize;
			//__debugbreak();
			status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3filebuffer, 0, &r3filesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!NT_SUCCESS(status))
				break;
			DbgPrint("<222>---\n");
			RtlZeroMemory(pr3filebuffer, r3filesize);

			shellsize = sizeof(MmLoadShell_x64);

			status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3shellbuffer, 0, &shellsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (!NT_SUCCESS(status))
				break;

			DbgPrint("<333>---\n");
			RtlZeroMemory(pr3shellbuffer, shellsize);

			RtlCopyMemory(pr3filebuffer, filebuffer, shellsize);

			*(ULONG64*)((ULONG64)MmLoadShell_x64 + 0x511) = (ULONG64)pr3imagebuffer;
			RtlCopyMemory(pr3shellbuffer, MmLoadShell_x64, sizeof(MmLoadShell_x64));


			DbgPrintEx(77, 0, "pr3shellbuffer%p\n", pr3shellbuffer);















			ntdllbase11 = AsdGetProcessMoudleBase(PsGetCurrentProcess(), L"kernel32.dll");
			if (ntdllbase11 == 0)
			{
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			Create = (ULONG_PTR)AsdGetModuleExport((PVOID)ntdllbase11, "CreateThread");
			if (Create == 0)
			{
				status = STATUS_UNSUCCESSFUL;
				break;
			}







			Read = (ULONG_PTR)AsdGetModuleExport((PVOID)ntdllbase11, "ReadProcessMemory");
			if (Read == 0)
			{
				status = STATUS_UNSUCCESSFUL;
				break;
			}





			unsigned char code66[] =
			{
				0x48 ,0x83 ,0xEC ,0x38 ,0x33 ,0xC0,
				0x49,0xB8,0,0,0,0,0,0,0,0,


				0x49,0xB9,0,0,0,0,0,0,0,0,
				0x48 ,0x89 ,0x44 ,0x24 ,0x28 ,0x33 ,0xD2 ,0x89 ,0x44 ,0x24 ,0x20 ,0x33 ,0xC9,

				0xFF,0x15,02,0,0,0,

				0xEB,0x8,
				0,0,0,0,0,0,0,0,

				0x48 ,0x83 ,0xC4 ,0x38 ,0xC3



			};
			startaddresss555 = (PVOID)((ULONG64)Read + 8);
			*(ULONG64*)(code66 + 18) = pr3filebuffer;
			//*(ULONG64*)(code66 + 8) = 地址 + mmsize;
			*(ULONG64*)(code66 + 8) = (ULONG64)startaddresss555;



			BYTE codeiii[] = {

				0x49 ,0xB8 ,0x00 ,00 ,00 ,00 ,00 ,00 ,00 ,00 ,0x41,0xFF ,0xE0
			};


			*(ULONG64*)(codeiii + 2) = (ULONG64)pr3shellbuffer;




			*(ULONG64*)(code66 + 40 + 10 - 3) = (ULONG64)Create;



			MDLMoveMemory((void*)(startaddresss555), codeiii, sizeof(codeiii));


			SIZE_T size = 0x1000;
			status = ZwAllocateVirtualMemory(NtCurrentProcess(), &shell, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!NT_SUCCESS(status))
				break;
			memcpy((void*)shell, code66, sizeof(code66));
			//MDLMoveMemory((void*)(shell), code66, sizeof(code66));
			DbgPrintEx(77, 0, "shell%p\n", shell);
			











			status = STATUS_SUCCESS;
			break;

		} while (1);

	}except(1) {



		DbgPrintEx(77, 0, "异常\n");
	}
	


















	KeUnstackDetachProcess(&kapcs);
	//return 0;

	MySleep(20000);

	调用exe函数Ex(pid,shell);
	
	

	
	return status;
}

//有线程shellcode注入
NTSTATUS AsdKernelMapInject(DWORD pid, PVOID filebuffer, SIZE_T filesize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PEPROCESS tempep = NULL;

	KAPC_STATE  kapcs = { 0 };

	BOOLEAN battached = FALSE;


	SIZE_T shellsize = 0, r3filesize = 0, r3imagesize = 0, ntimagesize = 0;

	PVOID pr3filebuffer = NULL, pr3shellbuffer = NULL, pr3imagebuffer = NULL;

	PIMAGE_DOS_HEADER pdos = NULL;

	PIMAGE_NT_HEADERS pnt = NULL;

	HANDLE hthread = NULL;

	PETHREAD pthreadobj = NULL;


	do
	{
		status = PsLookupProcessByProcessId((HANDLE)pid, &tempep);
		if (!NT_SUCCESS(status))
			break;
		KeStackAttachProcess(tempep, &kapcs);
		battached = TRUE;

		pdos = (PIMAGE_DOS_HEADER)filebuffer;

		pnt = (PIMAGE_NT_HEADERS64)((PUCHAR)filebuffer + pdos->e_lfanew);

		ntimagesize = pnt->OptionalHeader.SizeOfImage;

		r3imagesize = ntimagesize;

		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3imagebuffer, 0, &r3imagesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status))
			break;

		RtlZeroMemory(pr3imagebuffer, r3imagesize);

		r3filesize = filesize;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3filebuffer, 0, &r3filesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status))
			break;
		RtlZeroMemory(pr3filebuffer, r3filesize);

		shellsize = sizeof(MmLoadShell_x64);
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pr3shellbuffer, 0, &shellsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status))
			break;
		RtlZeroMemory(pr3shellbuffer, shellsize);

		RtlCopyMemory(pr3filebuffer, filebuffer, filesize);

		*(PULONG_PTR)((PBYTE)MmLoadShell_x64 + 0x511) = (ULONG_PTR)pr3imagebuffer;

		RtlCopyMemory(pr3shellbuffer, MmLoadShell_x64, sizeof(MmLoadShell_x64));
		DbgPrintEx(77, 0, "pr3shellbuffer%p\n", pr3shellbuffer);
		//创建线程 执行shell
		MySleep(20000);
		status = NtCreateThreadEx(&hthread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), pr3shellbuffer, pr3filebuffer, 0, 0, 0x10000, 0x20000, NULL);
		
		DbgPrintEx(77, 0, "status%p\n", status);
		
		if (!NT_SUCCESS(status))
			break;
		status = ObReferenceObjectByHandle(hthread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &pthreadobj, NULL);
		ZwClose(hthread);
		if (NT_SUCCESS(status))
		{
			DbgPrintEx(77, 0, "SUCCESS");
			KeWaitForSingleObject(pthreadobj, Executive, KernelMode, FALSE, NULL);
			ObDereferenceObject(pthreadobj);
		}
		status = STATUS_SUCCESS;
		break;

	} while (1);
	if (battached)
	{
		if (pr3filebuffer)
		{
			RtlZeroMemory(pr3filebuffer, r3filesize);
			ZwFreeVirtualMemory(NtCurrentProcess(), &pr3filebuffer, &r3filesize, MEM_RELEASE);

		}
		if (pr3shellbuffer)
		{
			RtlZeroMemory(pr3shellbuffer, shellsize);
			ZwFreeVirtualMemory(NtCurrentProcess(), &pr3shellbuffer, &shellsize, MEM_RELEASE);
		}
		KeUnstackDetachProcess(&kapcs);

	}
	return status;


}

//有模块注入
NTSTATUS AsdKernelLdrDllInject(DWORD pid)
{
	UNICODE_STRING dllpath = { 0 };

	NTSTATUS       status = STATUS_UNSUCCESSFUL;

	PEPROCESS      tempep = NULL;

	KAPC_STATE     kapcs = { 0 };

	PBYTE          threadstart = NULL;

	BOOLEAN        battached = FALSE;

	ULONG_PTR      ldrloaddlladdr = 0;

	ULONG_PTR      ntdllbase = 0;

	SIZE_T         shellsize = 0, outsize = 0;

	HANDLE         hthread = NULL;

	PETHREAD       pthreadobj = NULL;

	do
	{
		status = PsLookupProcessByProcessId((HANDLE)pid, &tempep);

		if (!NT_SUCCESS(status))
			break;

		ObReferenceObject(tempep);

		KeStackAttachProcess(tempep, &kapcs);

		battached = TRUE;

		RtlInitUnicodeString(&dllpath, DLL_PATH);

		ntdllbase = AsdGetProcessMoudleBase(PsGetCurrentProcess(), L"ntdll.dll");
		if (ntdllbase == 0)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ldrloaddlladdr = (ULONG_PTR)AsdGetModuleExport((PVOID)ntdllbase, "LdrLoadDll");
		if (ldrloaddlladdr == 0)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		shellsize = PAGE_SIZE;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &threadstart, 0, &shellsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		RtlZeroMemory(threadstart, PAGE_SIZE);

		RtlCopyMemory(threadstart + 0x500, dllpath.Buffer, dllpath.Length);
		dllpath.Buffer = (PWCHAR)(threadstart + 0x500);
		dllpath.MaximumLength = 0x500;
		RtlCopyMemory(threadstart + 0x200, &dllpath, sizeof(dllpath));

		*(PULONG64)(InJectDllx64 + 2) = (ULONG64)ldrloaddlladdr;
		*(PULONG64)(InJectDllx64 + 16) = (ULONG64)(threadstart + 0x200);
		*(PULONG64)(InJectDllx64 + 26) = (ULONG64)(threadstart + 0x300);
		RtlCopyMemory(threadstart, InJectDllx64, sizeof(InJectDllx64));

		status = NtCreateThreadEx(&hthread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), threadstart, NULL, 0, 0, 0x10000, 0x2000, NULL);
		if (!NT_SUCCESS(status))
			break;
		status = ObReferenceObjectByHandle(hthread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &pthreadobj, NULL);
		ZwClose(hthread);

		if (NT_SUCCESS(status))
		{
			KeWaitForSingleObject(pthreadobj, Executive, KernelMode, FALSE, NULL);
			ObDereferenceObject(pthreadobj);
		}
		status = STATUS_SUCCESS;
		break;
	} while (1);
	if(battached)
	{
		if (threadstart);
		{
			RtlZeroMemory(threadstart, PAGE_SIZE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &threadstart, &shellsize, MEM_RELEASE);
		}
		KeUnstackDetachProcess(&kapcs);
	}
	return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("[+]DriverUnload:Success\n");
}


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;      //下一个结构的偏移量，最后一个偏移量为0
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;     //进程名
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;               //进程ID
	HANDLE InheritedFromUniqueProcessId;   //父进程ID
	ULONG HandleCount;
	ULONG SessionId;       //会话ID                    
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;
typedef NTSTATUS(*PZwQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);






 HANDLE GetProcessId_byName(PCHAR findname, SIZE_T bufsize)
{
	UNICODE_STRING temp = { 0 };
	RtlInitUnicodeString(&temp, L"ZwQuerySystemInformation");
	PZwQuerySystemInformation pfunc = NULL;

	pfunc = (PZwQuerySystemInformation)MmGetSystemRoutineAddress(&temp);

	ULONG length = 0;
	pfunc((SYSTEM_INFORMATION_CLASS)5, NULL, 0, &length);


	PVOID newmem = NULL;

	newmem = ExAllocatePool(NonPagedPool, length);

	pfunc((SYSTEM_INFORMATION_CLASS)5, newmem, length, &length);
	PVOID ptemp = newmem;
	PSYSTEM_PROCESS_INFORMATION info = (PSYSTEM_PROCESS_INFORMATION)ptemp;

	do
	{
		if (MmIsAddressValid(&info->ImageName) && MmIsAddressValid(info->ImageName.Buffer))
		{


			ANSI_STRING ansi = { 0 };


			RtlUnicodeStringToAnsiString(&ansi, &info->ImageName, TRUE);
			CHAR buf[500] = { 0 };
			RtlCopyMemory(buf, ansi.Buffer, ansi.Length);





			if (strcmp(buf, findname) == 0)
			{


				return info->UniqueProcessId;
			}




		}
		*(ULONG64*)&ptemp = (ULONG64)ptemp + info->NextEntryOffset;
		info = (PSYSTEM_PROCESS_INFORMATION)ptemp;




	} while (info->NextEntryOffset != 0);


	return (HANDLE)0;

}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING Driver_Reg)
{
	DWORD pid = 0;
	PVOID kfilebuffer = NULL;
	SIZE_T mmsize = 0;
//	DriverObject->DriverUnload = DriverUnload;
	ULONGLONG Temp_table = GetKeServiceDescriptorTable64_2();
	if (Temp_table == 0)
	{
		Temp_table = GetKeServiceDescriptorTable64();
		if (Temp_table == 0)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}
	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)Temp_table;
	NtCreateThreadEx = (fn_NtCreateThreadEx)(GetSSDTFuncCurAddr(GetIndexByName((UCHAR*)"NtCreateThreadEx")));
char buf[] = "hallclient.exe";
	
	//AsdKernelMapInject
	//char buf[] = "寄生.vmp(4).exe";

	if (NtCreateThreadEx == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrintEx(77, 0, "NtCreateThreadEx  %p\n", NtCreateThreadEx);
	pid = GetProcessId_byName(buf,sizeof(buf));
	
	if (pid)
	{
	
		DbgPrintEx(77, 0, "pid  %p\n", pid);
	kfilebuffer = AsdReadFiletoKernelMM(L"\\??\\C:\\SSJJ2.vmp.dll", &mmsize);
		//L"C:\\SSJJ2.vmp.dll"

		

		DbgPrintEx(77, 0, " kfilebuffer  %p\n", kfilebuffer);
		if(kfilebuffer)
		{
		
			//AsdKernelApcMapInject(pid, kfilebuffer, mmsize);
		//	AsdKernelMapInject(pid, kfilebuffer, mmsize);
		AsdKernelApcMapInjectEx(pid, kfilebuffer, mmsize);
		//	AsdKernelMapInject(pid, kfilebuffer, mmsize);
			ExFreePool(kfilebuffer);
		}
	}
	return STATUS_UNSUCCESSFUL;
}




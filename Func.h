#pragma once
#include<ntifs.h>
#include<ntimage.h>

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	UINT16 LoadCount;
	UINT16 TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct
{
	union OD_OR_NAME
	{
		CHAR* Name;
		USHORT Od;
	};
}EXP_FUN_NAME;


//API导出模式
typedef enum
{
	NameFlag = 0x1,
	OrderFlag = 0x2,
}EXP_FUN_MODE;


// SSDT

typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PULONG ParamTableBase;
}KSYSTEM_SERVICE_TABLE, * PKSYSTEM_SERVICE_TABLE;


extern PVOID					g_pntKernelImageBuff;		 // 新内核
extern ULONG					g_ntKernelBase;				 // 老内核的加载基址
extern ULONG					g_ntKernelSize;				 // 老内核的映像大小
extern UNICODE_STRING			g_ntKernelPath;				 // 老内核文件路径
extern PKSYSTEM_SERVICE_TABLE	pNewSSDT;					 // 新的系统服务表 也是SSDT表地址


// 驱动卸载函数
VOID DriverUnload(PDRIVER_OBJECT pDriver);

// 获取内核文件的路径、大小、加载基址
NTSTATUS
GetKernelInfo(
	IN PDRIVER_OBJECT driver,
	OUT PULONG pKrnlBase,
	OUT PULONG uKrnlImageSize
);


// 读取内核文件到堆内存
NTSTATUS
LoadKernelFile(
	IN PUNICODE_STRING pKrnlFullPath,
	IN ULONG uKrnlImageSize,
	OUT PVOID* pKernelImageBuffer
);

// 获取模块基址
NTSTATUS
GetModuleBase(
	IN PDRIVER_OBJECT pDriver,
	IN PUNICODE_STRING pModuleName,
	OUT PVOID* pModuleBaase
);

//判断指定的地址是否在可执行的节中
BOOLEAN 
AddressIsExecuteable(
	IN ULONG pAddress,
	IN PIMAGE_SECTION_HEADER pSectionHeader,
	IN ULONG ulSectionNum
);



// 修复重定位表
NTSTATUS
RepairRelocation(
	IN OUT PVOID pKernelImageBuffer,
	IN ULONG KernelBase
);



// 获取导出函数地址
NTSTATUS
GetFunAddrOfModule(
	IN  PVOID pModule,
	IN  EXP_FUN_NAME unFuntionName,
	IN  EXP_FUN_MODE eMode,
	OUT PULONG FuncAddress
);


// 修复IAT
NTSTATUS
RepairIAT(
	IN PDRIVER_OBJECT pDriver,
	IN OUT PVOID pKernelImageBuffer
);

// 初始化新加载的内核的系统服务表，并且填充
PKSYSTEM_SERVICE_TABLE InitNewSSDT(
	IN PVOID pKernelImageBuffer,
	IN ULONG uKernelOldBase
);


// 页保护
void disablePageWriteProtect();
void enablePageWriteProtect();



// HOOK KiFastCallEntry,使调用号走新内核的路线
VOID 
installHook();

// SSDT过滤函数.
ULONG 
SSDTFilter(
	ULONG index,		/*索引号,也是调用号*/
	ULONG tableAddress,				/*表的地址,可能是SSDT表的地址,也可能是Shadow SSDT表的地址*/
	PULONG funAddr					 /*从表中取出的函数地址*/
);


// inline hook KiFastCallEntry的函数
void myKiFastEntryHook();
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


//API����ģʽ
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


extern PVOID					g_pntKernelImageBuff;		 // ���ں�
extern ULONG					g_ntKernelBase;				 // ���ں˵ļ��ػ�ַ
extern ULONG					g_ntKernelSize;				 // ���ں˵�ӳ���С
extern UNICODE_STRING			g_ntKernelPath;				 // ���ں��ļ�·��
extern PKSYSTEM_SERVICE_TABLE	pNewSSDT;					 // �µ�ϵͳ����� Ҳ��SSDT���ַ


// ����ж�غ���
VOID DriverUnload(PDRIVER_OBJECT pDriver);

// ��ȡ�ں��ļ���·������С�����ػ�ַ
NTSTATUS
GetKernelInfo(
	IN PDRIVER_OBJECT driver,
	OUT PULONG pKrnlBase,
	OUT PULONG uKrnlImageSize
);


// ��ȡ�ں��ļ������ڴ�
NTSTATUS
LoadKernelFile(
	IN PUNICODE_STRING pKrnlFullPath,
	IN ULONG uKrnlImageSize,
	OUT PVOID* pKernelImageBuffer
);

// ��ȡģ���ַ
NTSTATUS
GetModuleBase(
	IN PDRIVER_OBJECT pDriver,
	IN PUNICODE_STRING pModuleName,
	OUT PVOID* pModuleBaase
);

//�ж�ָ���ĵ�ַ�Ƿ��ڿ�ִ�еĽ���
BOOLEAN 
AddressIsExecuteable(
	IN ULONG pAddress,
	IN PIMAGE_SECTION_HEADER pSectionHeader,
	IN ULONG ulSectionNum
);



// �޸��ض�λ��
NTSTATUS
RepairRelocation(
	IN OUT PVOID pKernelImageBuffer,
	IN ULONG KernelBase
);



// ��ȡ����������ַ
NTSTATUS
GetFunAddrOfModule(
	IN  PVOID pModule,
	IN  EXP_FUN_NAME unFuntionName,
	IN  EXP_FUN_MODE eMode,
	OUT PULONG FuncAddress
);


// �޸�IAT
NTSTATUS
RepairIAT(
	IN PDRIVER_OBJECT pDriver,
	IN OUT PVOID pKernelImageBuffer
);

// ��ʼ���¼��ص��ں˵�ϵͳ������������
PKSYSTEM_SERVICE_TABLE InitNewSSDT(
	IN PVOID pKernelImageBuffer,
	IN ULONG uKernelOldBase
);


// ҳ����
void disablePageWriteProtect();
void enablePageWriteProtect();



// HOOK KiFastCallEntry,ʹ���ú������ں˵�·��
VOID 
installHook();

// SSDT���˺���.
ULONG 
SSDTFilter(
	ULONG index,		/*������,Ҳ�ǵ��ú�*/
	ULONG tableAddress,				/*��ĵ�ַ,������SSDT��ĵ�ַ,Ҳ������Shadow SSDT��ĵ�ַ*/
	PULONG funAddr					 /*�ӱ���ȡ���ĺ�����ַ*/
);


// inline hook KiFastCallEntry�ĺ���
void myKiFastEntryHook();
#include"Func.h"

PVOID				g_pntKernelImageBuff = NULL;     // 新内核
ULONG				g_ntKernelBase = 0;				 // 老内核的加载基址
ULONG				g_ntKernelSize = 0;				 // 老内核的映像大小
UNICODE_STRING		g_ntKernelPath = { 0 };			 // 老内核文件路径
PKSYSTEM_SERVICE_TABLE pNewSSDT = 0;					 // 新的系统服务表 也是SSDT表地址

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath) {
	NTSTATUS					status = STATUS_SUCCESS;

	pDriver->DriverUnload = DriverUnload;
	DbgPrint("我是驱动,我运行了\t\n");

	RtlInitUnicodeString(&g_ntKernelPath, L"\\??\\C:\\WINDOWS\\system32\\ntkrnlpa.exe");

	// 获取需要的内核文件信息
	status = GetKernelInfo(pDriver, &g_ntKernelBase, &g_ntKernelSize);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("GetKernelInfo failed!\t\n");
		return status;
	}

	// 接下来就是把内核文件加载到堆里，然后利用PE相关的知识把它恢复成内存中的状态
	status = LoadKernelFile(&g_ntKernelPath, g_ntKernelSize, &g_pntKernelImageBuff);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("LoadKernelFile failed!\t\n");
		return status;
	}

	//__asm int 3;
	// 修复重定位表
	status = RepairRelocation(g_pntKernelImageBuff, g_ntKernelBase);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("RepairRelocation failed!\t\n");
		return status;
	}
	//__asm int 3;
	// 修复IAT表
	status = RepairIAT(pDriver, g_pntKernelImageBuff);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("RepairIAT failed!\t\n");
		return status;
	}

	// 初始化新的SSDT表
	pNewSSDT = InitNewSSDT(g_pntKernelImageBuff, g_ntKernelBase);
	// DbgPrint("pNewSSDT:[%X]\t\n", pNewSSDT);


	// 开始HOOK KiFastCallEntry
	installHook();
	return status;
}
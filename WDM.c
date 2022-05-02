#include"Func.h"

PVOID				g_pntKernelImageBuff = NULL;     // ���ں�
ULONG				g_ntKernelBase = 0;				 // ���ں˵ļ��ػ�ַ
ULONG				g_ntKernelSize = 0;				 // ���ں˵�ӳ���С
UNICODE_STRING		g_ntKernelPath = { 0 };			 // ���ں��ļ�·��
PKSYSTEM_SERVICE_TABLE pNewSSDT = 0;					 // �µ�ϵͳ����� Ҳ��SSDT���ַ

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath) {
	NTSTATUS					status = STATUS_SUCCESS;

	pDriver->DriverUnload = DriverUnload;
	DbgPrint("��������,��������\t\n");

	RtlInitUnicodeString(&g_ntKernelPath, L"\\??\\C:\\WINDOWS\\system32\\ntkrnlpa.exe");

	// ��ȡ��Ҫ���ں��ļ���Ϣ
	status = GetKernelInfo(pDriver, &g_ntKernelBase, &g_ntKernelSize);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("GetKernelInfo failed!\t\n");
		return status;
	}

	// ���������ǰ��ں��ļ����ص����Ȼ������PE��ص�֪ʶ�����ָ����ڴ��е�״̬
	status = LoadKernelFile(&g_ntKernelPath, g_ntKernelSize, &g_pntKernelImageBuff);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("LoadKernelFile failed!\t\n");
		return status;
	}

	//__asm int 3;
	// �޸��ض�λ��
	status = RepairRelocation(g_pntKernelImageBuff, g_ntKernelBase);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("RepairRelocation failed!\t\n");
		return status;
	}
	//__asm int 3;
	// �޸�IAT��
	status = RepairIAT(pDriver, g_pntKernelImageBuff);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("RepairIAT failed!\t\n");
		return status;
	}

	// ��ʼ���µ�SSDT��
	pNewSSDT = InitNewSSDT(g_pntKernelImageBuff, g_ntKernelBase);
	// DbgPrint("pNewSSDT:[%X]\t\n", pNewSSDT);


	// ��ʼHOOK KiFastCallEntry
	installHook();
	return status;
}
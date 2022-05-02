#include "Func.h"

//��ȡSSDT�ĵ�������
extern PKSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

// ��ת��ȥ
ULONG g_hookAddr_next_ins = 0;

VOID DriverUnload(PDRIVER_OBJECT pDriver) {

	// ж��HOOK

	// �ȴ�3����ͷ��¼��ص��ں˿ռ�

	// ̫̫���ˡ�������ʱ���ڸ�

	DbgPrint("������������ж����\t\n");
}

NTSTATUS GetKernelInfo(IN PDRIVER_OBJECT driver, OUT PULONG pKrnlBase, OUT PULONG uKrnlImageSize)
{
	PLDR_DATA_TABLE_ENTRY pLdteHead; // �ں�ģ������ͷ
	PLDR_DATA_TABLE_ENTRY pLdteCur; // ����ָ��
	UNICODE_STRING usBaseDllNameNtoskrnl, usDllNameNtkrnlpa; // �ں�ģ����

	//���ַ�ҳģʽ�µ��ں�ģ��
	RtlInitUnicodeString(&usBaseDllNameNtoskrnl, L"ntoskrnl.exe");
	RtlInitUnicodeString(&usDllNameNtkrnlpa, L"ntkrnlpa.exe");

	pLdteHead = (PLDR_DATA_TABLE_ENTRY)driver->DriverSection;
	pLdteCur = pLdteHead;
	do
	{
		if (
			(
				(RtlCompareUnicodeString(&pLdteCur->BaseDllName, &usBaseDllNameNtoskrnl, TRUE))
				||
				(RtlCompareUnicodeString(&pLdteCur->BaseDllName, &usBaseDllNameNtoskrnl, TRUE))
				) == 0
			)
		{
			*pKrnlBase = (PULONG)(pLdteCur->DllBase);
			*uKrnlImageSize = (ULONG)pLdteCur->SizeOfImage;

			return STATUS_SUCCESS;
		}
		pLdteCur = (PLDR_DATA_TABLE_ENTRY)pLdteCur->InLoadOrderLinks.Flink;
	} while (pLdteHead != pLdteCur);


	DbgPrint("û���ҵ��ں�ģ��\t\n");
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS LoadKernelFile(IN PUNICODE_STRING pKrnlFullPath, IN ULONG uKrnlImageSize, OUT PVOID* pKernelImageBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	// ��ȡ�ļ��е��ں�ģ��
	// ���ں�ģ����Ϊ�ļ�����
	HANDLE hFile = NULL;
	// ��ʼ��OBJECT_ATTRIBUTES������
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG ulAttributes = OBJ_CASE_INSENSITIVE /*�����ִ�Сд*/ | OBJ_KERNEL_HANDLE /*�ں˾��*/;
	InitializeObjectAttributes(
		&objAttrib,		    // ���س�ʼ����ϵĽṹ��
		pKrnlFullPath,      // �ļ���������
		ulAttributes,		// ��������
		NULL, NULL);		// һ��ΪNULL

	IO_STATUS_BLOCK StatusBlock = { 0 };

	ULONG read = 0;
	//DbgPrint("%ws\t\n", pKrnlFullPath->Buffer);

	// ���ļ�
	status = ZwCreateFile(
		&hFile,						// �����ļ����
		FILE_READ_DATA,             // �ļ��������� GENERIC_READ  FILE_READ_DATA
		&objAttrib,					// OBJECT_ATTRIBUTES
		&StatusBlock,				// ���ܺ����Ĳ������
		0,							// ��ʼ�ļ���С
		FILE_ATTRIBUTE_NORMAL,		// �½��ļ�������
		FILE_SHARE_READ,			// �ļ�����ʽ
		FILE_OPEN_IF,				// �ļ��������
		FILE_NON_DIRECTORY_FILE,    // �򿪲����ĸ��ӱ�־λ
		NULL,						// ��չ������
		0);							// ��չ����������

	if (STATUS_SUCCESS != status)
	{
		DbgPrint("���ļ�ʧ��\n");
		DbgPrint("%X\t\n", StatusBlock.Status);
		DbgPrint("%X\t\n", status);
		DbgPrint("%X\t\n", hFile);
		return status;
	}

	// ��ȡ�ļ����ݵ�������,

	*pKernelImageBuffer = ExAllocatePoolWithTag(NonPagedPool, uKrnlImageSize, "Ibuf");
	if (pKernelImageBuffer == NULL)
	{
		DbgPrint(("ExAllocatePool Failed!\r\n"));
		ZwClose(hFile);
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(*pKernelImageBuffer, uKrnlImageSize);

	//��ȡ�ļ���С
	FILE_STANDARD_INFORMATION fsi;
	status = ZwQueryInformationFile(hFile, &StatusBlock, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(("ZwQueryInformationFile Failed!\r\n"));
		ZwClose(hFile);
		return -1;
	}

	ULONG dwSize = fsi.EndOfFile.QuadPart;

	//�����ڴ�
	PVOID pFileBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, dwSize, "fbuf");
	if (pFileBuffer == NULL)
	{
		ExFreePoolWithTag(*pKernelImageBuffer, "Ibuf");
		ZwClose(hFile);
		DbgPrint(("ExAllocatePool Failed!\r\n"));
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(pFileBuffer, dwSize);

	//��ȡ�ļ�
	status = ZwReadFile(
		hFile,
		NULL,
		NULL,
		NULL,
		&StatusBlock,
		pFileBuffer,
		dwSize,
		&read,
		0);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(*pKernelImageBuffer, "Ibuf");
		ExFreePoolWithTag(pFileBuffer, "fbuf");
		ZwClose(hFile);
		DbgPrint(("Read ImageDosHeader Failed!"));
		return status;
	}

	ZwClose(hFile);

	if (dwSize == -1)
	{
		DbgPrint("CkReadFile failed!\r\n");
		return status;
	}
	// ������ڴ��е�PE״̬
	// ��ȡPEͷ��Ϣ �������ͷ�ļ� ntimage.h
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pFileBuffer);
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (ULONG)pDosHeader);

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	memcpy(*pKernelImageBuffer, pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

	for (size_t i = pNtHeader->FileHeader.NumberOfSections; i > 0; i--) {

		memcpy(
			(PVOID)(
				(ULONG)(*pKernelImageBuffer)
				+
				(ULONG)(pSectionHeader->VirtualAddress)),				//���Ƶ�VirtualAddress
			(PVOID)((ULONG)pFileBuffer
				+
				(ULONG)(pSectionHeader->PointerToRawData)),				//��ԭ����PointerToRawData
			pSectionHeader->SizeOfRawData 								//���ƶ��SizeOfRawData
		);
		pSectionHeader++;
	}

	return status;
}

NTSTATUS GetModuleBase(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pModuleName, OUT PVOID* pModuleBaase)
{
	NTSTATUS status = STATUS_SUCCESS;

	PLDR_DATA_TABLE_ENTRY pLdteHead; // �ں�ģ������ͷ
	PLDR_DATA_TABLE_ENTRY pLdteCur; // ����ָ��

	pLdteHead = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	pLdteCur = pLdteHead;
	do
	{
		if (0 == RtlCompareUnicodeString(&pLdteCur->BaseDllName, pModuleName, TRUE))
		{
			*pModuleBaase = (PULONG)(pLdteCur->DllBase);

			return STATUS_SUCCESS;
		}
		pLdteCur = (PLDR_DATA_TABLE_ENTRY)pLdteCur->InLoadOrderLinks.Flink;
	} while (pLdteHead != pLdteCur);

	DbgPrint("û���ҵ�ģ��\t\n");

	return STATUS_UNSUCCESSFUL;
}

BOOLEAN AddressIsExecuteable(IN ULONG pAddress, IN PIMAGE_SECTION_HEADER pSectionHeader, IN ULONG ulSectionNum)
{
	BOOLEAN bFlag = FALSE;
	
	//ѭ���ж��������ĸ�����
	for (int t = 0; t < ulSectionNum; t++)
	{
		//�ڵ���ʼ�ͽ���λ��
		ULONG Begin = pSectionHeader[t].VirtualAddress;
		ULONG End = pSectionHeader[t].VirtualAddress + pSectionHeader[t].Misc.VirtualSize;

		//DbgPrint("pSectionHeader:[%X]\t\n", pSectionHeader);
		//DbgPrint("Begin:[%X]\t\n", Begin);
		//DbgPrint("End:[%X]\t\n", End);
		//DbgPrint("pSectionHeader[t].Characteristics:[%X]\t\n", pSectionHeader[t].Characteristics);

		//__asm int 3;
		//�ж�
		if (pAddress >= Begin && pAddress <= End)
		{
			bFlag = ((pSectionHeader[t].Characteristics & 0x20000020) == 0x20000020) ? TRUE : FALSE;

			return bFlag;
		}
	}
	DbgPrint("pAddress:[%X] not in the section \t\n", pAddress);
	return bFlag;
}


NTSTATUS RepairRelocation(IN OUT PVOID pKernelImageBuffer, IN ULONG KernelBase)
{
	typedef struct _TYPE {
		USHORT Offset : 12;
		USHORT Type : 4;
	}TypeOffset, * PTypeOffset;

	NTSTATUS status = STATUS_SUCCESS;

	// PE ͷ �����ض�λ��
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pKernelImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (ULONG)pKernelImageBuffer);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((ULONG)pNtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((ULONG)pFileHeader + (ULONG)IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_BASE_RELOCATION pReloc = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (ULONG)pDosHeader;

	ULONG Items = 0, Items1 = 0, Items2 = 0;

	//  �����ض�λ������Ŀ���������ض�λ
	while (pReloc->SizeOfBlock && pReloc->VirtualAddress)
	{
		// �ض�λ����Ŀ
		ULONG ulCount = (pReloc->SizeOfBlock - 8) / 2;
		// ��Ҫ��λ���ݵ���ʼRVA
		ULONG ulRva = pReloc->VirtualAddress;
		// ������Ҫ�ض�λ������
		PTypeOffset pRelocationArray = (PTypeOffset)(pReloc + 1);

		for (int i = 0; i < ulCount; i++)
		{
			// ��Ҫ�ض�λ������λ�� = ImageBase + VirtualAddress + TypeOffset��12λ
			if (pRelocationArray->Type == 3)
			{
				//��ȡҪ�޸ĵĵ�ַ��RVA
				ULONG RepairAddrOffset = (ulRva + pRelocationArray->Offset);

				// �ж�Ҫ�޸��ĵ�ַ�Ƿ���
				if (AddressIsExecuteable(RepairAddrOffset, pSectionHeader, pFileHeader->NumberOfSections))
				{
					PULONG pRepairAddr = (PULONG)(RepairAddrOffset + (ULONG)pKernelImageBuffer);
					//������Ҫ�ض�λ��������ں��е�ֵ
					*pRepairAddr += (ULONG)pKernelImageBuffer - KernelBase;
					Items++;
					Items1++;
				}
				else
				{
					// ����Ҫ�޸���ֵ�� ʲô���������С�
					//DbgPrint("FixAddress to Old Kernel:[%X]\t\n", *pRepairAddr);
					Items++;
					Items2++;
				}
				
			}
			pRelocationArray++;
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((ULONG)pReloc + pReloc->SizeOfBlock);
	}
	DbgPrint("Items: [%X],Items1: [%X], Items2: [%X]\t\n", Items, Items1, Items2);
	return status;
}

NTSTATUS GetFunAddrOfModule(IN PVOID pModule, IN EXP_FUN_NAME unFuntionName, IN EXP_FUN_MODE eMode, OUT PULONG FuncAddress)
{
	//__asm int 3;
	NTSTATUS status = STATUS_SUCCESS;

	// PE ���ҵ�����
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModule;
	//DbgPrint("pDosHeader:%X\t\n", pDosHeader);
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (ULONG)pModule);
	//DbgPrint("pNtHeader:%X\t\n", pNtHeader);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((ULONG)pNtHeader + 4);
	//DbgPrint("pFileHeader:%X\t\n", pFileHeader);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((ULONG)pFileHeader + (ULONG)IMAGE_SIZEOF_FILE_HEADER);
	//DbgPrint("pOptionHeader:%X\t\n", pOptionHeader);
	PIMAGE_DATA_DIRECTORY pDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;
	//DbgPrint("pDirectory:%X\t\n", pDirectory);
	PIMAGE_EXPORT_DIRECTORY pExportTabel = (PIMAGE_EXPORT_DIRECTORY)((ULONG)pModule + pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	//DbgPrint("pExportTabel:%X\t\n", pExportTabel);


	//__asm int 3;
	PULONG dwNameTable = (PULONG)((ULONG)pModule + (pExportTabel->AddressOfNames));

	PUSHORT wOrdinalsTable = (PUSHORT)((ULONG)pModule + (pExportTabel->AddressOfNameOrdinals));

	PULONG dwAddressTable = (PULONG)((ULONG)pModule + (pExportTabel->AddressOfFunctions));

	
	int i = 0;
	if (eMode == NameFlag)//�����Ƶ���
	{
		for (i = 0; i < (int)(pExportTabel->NumberOfNames); ++i)
		{
			CHAR* cImportName = (CHAR*)((ULONG)pModule + dwNameTable[i]);

			if (strcmp(cImportName, unFuntionName.Name) == 0)
			{
				break;
			}

		}
		*FuncAddress = ((ULONG)pModule + dwAddressTable[wOrdinalsTable[i]]);

	}
	else//����ŵ���
	{
		*FuncAddress = (ULONG)pModule + dwAddressTable[(unFuntionName.Od) - (pExportTabel->Base)];
	}

	if (*FuncAddress != 0)
	{
		return STATUS_SUCCESS;
	}
	else
	{
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS RepairIAT(IN PDRIVER_OBJECT pDriver, IN OUT PVOID pKernelImageBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;

	// PE ͷ ��λ�����  IAT��
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pKernelImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (ULONG)pDosHeader);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = &pNtHeader->OptionalHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG)pDosHeader + pOptionHeader->DataDirectory[1].VirtualAddress);

		
	// ����INT��
	while (pImportTable->OriginalFirstThunk || pImportTable->FirstThunk)
	{
		// �����涨�壬������ֵÿ�ζ�����������Ϊ��

		//ģ���ַ
		PVOID pModuleBase = NULL;
		// ģ������
		CHAR szName[0x50] = { 0 };
		ANSI_STRING asName = { 0 };
		UNICODE_STRING usName = { 0 };


		// ��ȡģ����,��ģ�����ֻ�ȡģ���ַ
		PCHAR MdName = (PCHAR)(pImportTable->Name + (ULONG)pDosHeader);
		memcpy(szName, MdName, strlen(MdName));
		RtlInitAnsiString(&asName, szName);

		status = RtlAnsiStringToUnicodeString(&usName, &asName, TRUE);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("RtlAnsiStringToUnicodeString failed!\t\n");
			return status;
		}
		DbgPrint("usName:%ws\t\n", usName.Buffer);

		// ��ȡģ���ַ
		status = GetModuleBase(pDriver, &usName, &pModuleBase);
		
		if (!NT_SUCCESS(status))
		{
			RtlFreeUnicodeString(&usName);
			DbgPrint("GetModuleBase failed!\t\n");
			return status;
		}

		if (NULL == pModuleBase)
		{
			RtlFreeUnicodeString(&usName);
			DbgPrint("ModuleBase = 0 !\t\n");
			return STATUS_UNSUCCESSFUL;
		}

		// �޸�IAT��

		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((ULONG)pKernelImageBuffer + pImportTable->FirstThunk);

		while (*((PULONG)pThunkData) != 0)
		{
			EXP_FUN_NAME emFunName = { 0 };
			ULONG dwProcAddress = 0;

			//__asm int 3;
			// IMAGE_THUNK_DATA32 ��һ��4�ֽ�����
			// ������λ��1����ô��ȥ���λ���ǵ������
			// ������λ��0����ô���ֵ��RVA ָ�� IMAGE_IMPORT_BY_NAME
			if ((*((PULONG)pThunkData) & 0x80000000) == 0x80000000)
			{
				emFunName.Od = (*((PULONG)pThunkData) & 0x7FFFFFFF);
				status = GetFunAddrOfModule(pModuleBase, emFunName, OrderFlag, &dwProcAddress);
				if (!NT_SUCCESS(status))
				{
					RtlFreeUnicodeString(&usName);
					DbgPrint("1 GetFunAddrOfModule failed !\t\n");
					return STATUS_UNSUCCESSFUL;
				}
				DbgPrint("1 dwProcAddress:%X\t\n", dwProcAddress);
				*((PULONG)pThunkData) = dwProcAddress;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(*((PULONG)pThunkData) + (ULONG)pKernelImageBuffer);

				// �����ֵ���

				emFunName.Name = pIBN->Name;
				status = GetFunAddrOfModule(pModuleBase, emFunName, NameFlag, &dwProcAddress);
				if (!NT_SUCCESS(status))
				{
					RtlFreeUnicodeString(&usName);
					DbgPrint("2 GetFunAddrOfModule failed !\t\n");
					return STATUS_UNSUCCESSFUL;
				}
				DbgPrint("2 dwProcAddress:%X\t\n", dwProcAddress);
				*((PULONG)pThunkData) = dwProcAddress;
			}
			pThunkData++;
		}
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG)pImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

	return status;
}

PKSYSTEM_SERVICE_TABLE InitNewSSDT(IN PVOID pKernelImageBuffer, IN ULONG uKernelOldBase)
{
	//���ں˵�ַ-���ں˵�ַ���õ����ƫ��
	ULONG uNewKernelInc = (ULONG)pKernelImageBuffer - uKernelOldBase;

	//DbgPrint("KeServiceDescriptorTable: [%X]\r\n", KeServiceDescriptorTable);
	//DbgPrint("pKernelImageBuffer: [%X]\r\n", pKernelImageBuffer);
	//DbgPrint("uKernelOldBase: [%X]\r\n", uKernelOldBase);
	//DbgPrint("uNewKernelInc: [%X]\r\n", uNewKernelInc);
	// __asm int 3;


	//���ں˵�ssdtָ��������ƫ�ƣ��õ����ں˵�ssdtָ��

	PKSYSTEM_SERVICE_TABLE pNewSSDT = (PKSYSTEM_SERVICE_TABLE)((ULONG)KeServiceDescriptorTable + uNewKernelInc);


	if (!MmIsAddressValid(pNewSSDT))
	{
		DbgPrint("pNewSSDT is unaviable!\r\n");
		return;
	}


	// �����µ� SSDT ��Ա

	// ������ַ��
	pNewSSDT->ServiceTableBase = (PULONG)((ULONG)pKernelImageBuffer + (ULONG)(KeServiceDescriptorTable->ServiceTableBase) - uKernelOldBase );

	// ���α����޸�
	for (ULONG uIndex = 0; uIndex < KeServiceDescriptorTable->NumberOfServices; uIndex++)
	{
		// ����������һ���ӣ��һ������޸��ض�λʱ�Ŀӡ�������������ִ���޸��ض�λ�Ĵ���ǰ���˶ϵ㣬�鿴��һ�£�8�ɵĿ����ԡ�
		// pNewSSDT->ServiceTableBase[uIndex] += uNewKernelInc;
		// ������ַ�ټ�����Լ��ص�ַ���õ��µĵ�ssdt������ַ------����д�Ͳ����ض�λ���������ˡ�
		pNewSSDT->ServiceTableBase[uIndex] = KeServiceDescriptorTable->ServiceTableBase[uIndex] + uNewKernelInc;
	}

	if (!MmIsAddressValid(pNewSSDT->ServiceTableBase))
	{
		DbgPrint("pNewSSDT->ServiceTableBase: %X\r\n", pNewSSDT->ServiceTableBase);
		return;
	}

	// ��������
	pNewSSDT->NumberOfServices = KeServiceDescriptorTable->NumberOfServices;

	// ������Ժ���������ַ���ƫ��
	ULONG uOffset2 = (ULONG)KeServiceDescriptorTable->ParamTableBase - uKernelOldBase;
	
	// ����������
	pNewSSDT->ParamTableBase = (PULONG)((ULONG)pKernelImageBuffer + uOffset2);

	//DbgPrint("pNewSSDT->ServiceTableBase: %X\r\n", pNewSSDT->ServiceTableBase);
	//DbgPrint("pNewSSDT->NumberOfServices: %X\r\n", pNewSSDT->NumberOfServices);
	//DbgPrint("pNewSSDT->ParamTableBase: %X\r\n", pNewSSDT->ParamTableBase);

	//__asm int 3;
	return pNewSSDT;
}



// �ر��ڴ�ҳд�뱣��
void _declspec(naked) disablePageWriteProtect()
{
	_asm
	{
		push eax;
		mov eax, cr0;
		and eax, ~0x10000;
		mov cr0, eax;
		pop eax;
		ret;
	}
}

// �����ڴ�ҳд�뱣��
void _declspec(naked) enablePageWriteProtect()
{
	_asm
	{
		push eax;
		mov eax, cr0;
		or eax, 0x10000;
		mov cr0, eax;
		pop eax;
		ret;
	}
}

VOID installHook()
{
	ULONG g_hookAddr = 0;


	// �ҵ�KiFastCallEntry�����׵�ַ
	ULONG uKiFastCallEntry = 0;
	_asm
	{
		;// KiFastCallEntry������ַ����
		;// ������ģ��Ĵ�����0x176�żĴ�����
		pushad;
		mov ecx, 0x176; // ���ñ��
		rdmsr; ;// ��ȡ��edx:eax
		mov uKiFastCallEntry, eax;// ���浽����
		popad;
	}


	// �ҵ�HOOK��λ��, ������5�ֽڵ�����
	// 1 HOOK��λ��ѡ��Ϊ(�˴�����5�ֽ�,):
	//  2be1           sub     esp, ecx ;
	//  c1e902         shr     ecx, 2   ;
	UCHAR hookCode[5] = { 0x2b,0xe1,0xc1,0xe9,0x02 }; //����inline hook���ǵ�5�ֽ�

	ULONG i = 0;
	for (; i < 0x1FF; ++i)
	{
		if (RtlCompareMemory((UCHAR*)uKiFastCallEntry + i,
			hookCode,
			5) == 5)
		{
			break;
		}
	}
	if (i >= 0x1FF)
	{
		DbgPrint("��KiFastCallEntry������û���ҵ�HOOKλ��,����KiFastCallEntry�Ѿ���HOOK����\n");
		
		return;
	}

	g_hookAddr = uKiFastCallEntry + i;
	g_hookAddr_next_ins = g_hookAddr + 5;


	// ��ʼinline hook
	UCHAR jmpCode[5] = { 0xe9 };// jmp xxxx

	//__asm int 3;

	disablePageWriteProtect();

	// 1 ������תƫ��
	// ��תƫ�� = Ŀ���ַ - ��ǰ��ַ - 5
	*(ULONG*)(jmpCode + 1) = (ULONG)myKiFastEntryHook - g_hookAddr - 5;


	// 2 ����תָ��д��
	RtlCopyMemory(uKiFastCallEntry + i, jmpCode, 5);
	enablePageWriteProtect();
	//__asm int 3;
}

ULONG SSDTFilter(ULONG index, ULONG tableAddress, PULONG funAddr)
{
	
	//DbgPrint("index:[%X],tableAddress:[%X],funAddr:[%X]\t\n", index, tableAddress, funAddr);
	//__asm int 3;
	// �����SSDT��Ļ�
	if (tableAddress == KeServiceDescriptorTable->ServiceTableBase)
	{
		
		// �жϵ��ú�(0x&A��ZwOpenProcess�����ĵ��ú�)
		if (index == 0x7A)
		{
			// ������SSDT��ĺ�����ַ
			// Ҳ�������ں˵ĺ�����ַ
			DbgPrint("New\t\n");
			return pNewSSDT->ServiceTableBase[0x7A];
		}
	}
	// ���ؾɵĺ�����ַ
	return funAddr;
}

void _declspec(naked) myKiFastEntryHook()
{
	_asm
	{
		pushad; // ѹջ�Ĵ���: eax,ecx,edx,ebx, esp,ebp ,esi, edi
		pushfd; // ѹջ��־�Ĵ���


		push edx; // �ӱ���ȡ���ĺ�����ַ
		push edi; // ��ĵ�ַ
		push eax; // ���ú�
		call SSDTFilter; // ���ù��˺���


		;// �����������֮��ջ�ؼ�����,ָ��pushad��
		;// 32λ��ͨ�üĴ���������ջ��,ջ�ռ䲼��Ϊ:
		;// [esp + 00] <=> eflag
		;// [esp + 04] <=> edi
		;// [esp + 08] <=> esi
		;// [esp + 0C] <=> ebp
		;// [esp + 10] <=> esp
		;// [esp + 14] <=> ebx
		;// [esp + 18] <=> edx <<-- ʹ�ú�������ֵ���޸����λ��
		;// [esp + 1C] <=> ecx
		;// [esp + 20] <=> eax
		mov dword ptr ds : [esp + 0x18] , eax;
		popfd; // popfdʱ,ʵ����edx��ֵ�ͻᱻ�޸�
		popad;

		; //ִ�б�hook���ǵ�����ָ��
		sub esp, ecx;
		shr ecx, 2;
		jmp g_hookAddr_next_ins;
	}
}
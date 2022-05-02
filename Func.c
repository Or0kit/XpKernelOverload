#include "Func.h"

//获取SSDT的导出变量
extern PKSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

// 跳转回去
ULONG g_hookAddr_next_ins = 0;

VOID DriverUnload(PDRIVER_OBJECT pDriver) {

	// 卸载HOOK

	// 等待3秒后，释放新加载的内核空间

	// 太太懒了……，有时间在搞

	DbgPrint("我是驱动，我卸载了\t\n");
}

NTSTATUS GetKernelInfo(IN PDRIVER_OBJECT driver, OUT PULONG pKrnlBase, OUT PULONG uKrnlImageSize)
{
	PLDR_DATA_TABLE_ENTRY pLdteHead; // 内核模块链表头
	PLDR_DATA_TABLE_ENTRY pLdteCur; // 遍历指针
	UNICODE_STRING usBaseDllNameNtoskrnl, usDllNameNtkrnlpa; // 内核模块名

	//两种分页模式下的内核模块
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


	DbgPrint("没有找到内核模块\t\n");
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS LoadKernelFile(IN PUNICODE_STRING pKrnlFullPath, IN ULONG uKrnlImageSize, OUT PVOID* pKernelImageBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	// 获取文件中的内核模块
	// 将内核模块作为文件来打开
	HANDLE hFile = NULL;
	// 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG ulAttributes = OBJ_CASE_INSENSITIVE /*不区分大小写*/ | OBJ_KERNEL_HANDLE /*内核句柄*/;
	InitializeObjectAttributes(
		&objAttrib,		    // 返回初始化完毕的结构体
		pKrnlFullPath,      // 文件对象名称
		ulAttributes,		// 对象属性
		NULL, NULL);		// 一般为NULL

	IO_STATUS_BLOCK StatusBlock = { 0 };

	ULONG read = 0;
	//DbgPrint("%ws\t\n", pKrnlFullPath->Buffer);

	// 打开文件
	status = ZwCreateFile(
		&hFile,						// 返回文件句柄
		FILE_READ_DATA,             // 文件操作描述 GENERIC_READ  FILE_READ_DATA
		&objAttrib,					// OBJECT_ATTRIBUTES
		&StatusBlock,				// 接受函数的操作结果
		0,							// 初始文件大小
		FILE_ATTRIBUTE_NORMAL,		// 新建文件的属性
		FILE_SHARE_READ,			// 文件共享方式
		FILE_OPEN_IF,				// 文件存在则打开
		FILE_NON_DIRECTORY_FILE,    // 打开操作的附加标志位
		NULL,						// 扩展属性区
		0);							// 扩展属性区长度

	if (STATUS_SUCCESS != status)
	{
		DbgPrint("打开文件失败\n");
		DbgPrint("%X\t\n", StatusBlock.Status);
		DbgPrint("%X\t\n", status);
		DbgPrint("%X\t\n", hFile);
		return status;
	}

	// 读取文件内容到缓冲区,

	*pKernelImageBuffer = ExAllocatePoolWithTag(NonPagedPool, uKrnlImageSize, "Ibuf");
	if (pKernelImageBuffer == NULL)
	{
		DbgPrint(("ExAllocatePool Failed!\r\n"));
		ZwClose(hFile);
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(*pKernelImageBuffer, uKrnlImageSize);

	//获取文件大小
	FILE_STANDARD_INFORMATION fsi;
	status = ZwQueryInformationFile(hFile, &StatusBlock, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(("ZwQueryInformationFile Failed!\r\n"));
		ZwClose(hFile);
		return -1;
	}

	ULONG dwSize = fsi.EndOfFile.QuadPart;

	//分配内存
	PVOID pFileBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, dwSize, "fbuf");
	if (pFileBuffer == NULL)
	{
		ExFreePoolWithTag(*pKernelImageBuffer, "Ibuf");
		ZwClose(hFile);
		DbgPrint(("ExAllocatePool Failed!\r\n"));
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(pFileBuffer, dwSize);

	//读取文件
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
	// 拉伸成内存中的PE状态
	// 获取PE头信息 必须包含头文件 ntimage.h
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pFileBuffer);
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (ULONG)pDosHeader);

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	memcpy(*pKernelImageBuffer, pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

	for (size_t i = pNtHeader->FileHeader.NumberOfSections; i > 0; i--) {

		memcpy(
			(PVOID)(
				(ULONG)(*pKernelImageBuffer)
				+
				(ULONG)(pSectionHeader->VirtualAddress)),				//复制到VirtualAddress
			(PVOID)((ULONG)pFileBuffer
				+
				(ULONG)(pSectionHeader->PointerToRawData)),				//由原来的PointerToRawData
			pSectionHeader->SizeOfRawData 								//复制多大SizeOfRawData
		);
		pSectionHeader++;
	}

	return status;
}

NTSTATUS GetModuleBase(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pModuleName, OUT PVOID* pModuleBaase)
{
	NTSTATUS status = STATUS_SUCCESS;

	PLDR_DATA_TABLE_ENTRY pLdteHead; // 内核模块链表头
	PLDR_DATA_TABLE_ENTRY pLdteCur; // 遍历指针

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

	DbgPrint("没有找到模块\t\n");

	return STATUS_UNSUCCESSFUL;
}

BOOLEAN AddressIsExecuteable(IN ULONG pAddress, IN PIMAGE_SECTION_HEADER pSectionHeader, IN ULONG ulSectionNum)
{
	BOOLEAN bFlag = FALSE;
	
	//循环判断数据在哪个节中
	for (int t = 0; t < ulSectionNum; t++)
	{
		//节的起始和结束位置
		ULONG Begin = pSectionHeader[t].VirtualAddress;
		ULONG End = pSectionHeader[t].VirtualAddress + pSectionHeader[t].Misc.VirtualSize;

		//DbgPrint("pSectionHeader:[%X]\t\n", pSectionHeader);
		//DbgPrint("Begin:[%X]\t\n", Begin);
		//DbgPrint("End:[%X]\t\n", End);
		//DbgPrint("pSectionHeader[t].Characteristics:[%X]\t\n", pSectionHeader[t].Characteristics);

		//__asm int 3;
		//判断
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

	// PE 头 查找重定位表
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pKernelImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (ULONG)pKernelImageBuffer);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((ULONG)pNtHeader + 4);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((ULONG)pFileHeader + (ULONG)IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_BASE_RELOCATION pReloc = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (ULONG)pDosHeader;

	ULONG Items = 0, Items1 = 0, Items2 = 0;

	//  遍历重定位表，并对目标代码进行重定位
	while (pReloc->SizeOfBlock && pReloc->VirtualAddress)
	{
		// 重定位项数目
		ULONG ulCount = (pReloc->SizeOfBlock - 8) / 2;
		// 需要定位数据的起始RVA
		ULONG ulRva = pReloc->VirtualAddress;
		// 解析需要重定位的项数
		PTypeOffset pRelocationArray = (PTypeOffset)(pReloc + 1);

		for (int i = 0; i < ulCount; i++)
		{
			// 需要重定位的数据位置 = ImageBase + VirtualAddress + TypeOffset低12位
			if (pRelocationArray->Type == 3)
			{
				//获取要修改的地址的RVA
				ULONG RepairAddrOffset = (ulRva + pRelocationArray->Offset);

				// 判断要修复的地址是否在
				if (AddressIsExecuteable(RepairAddrOffset, pSectionHeader, pFileHeader->NumberOfSections))
				{
					PULONG pRepairAddr = (PULONG)(RepairAddrOffset + (ULONG)pKernelImageBuffer);
					//修正需要重定位项的在新内核中的值
					*pRepairAddr += (ULONG)pKernelImageBuffer - KernelBase;
					Items++;
					Items1++;
				}
				else
				{
					// 不需要修复的值。 什么都不做就行。
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

	// PE 查找导出表
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
	if (eMode == NameFlag)//按名称导出
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
	else//按序号导出
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

	// PE 头 定位大导入表  IAT表
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pKernelImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (ULONG)pDosHeader);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = &pNtHeader->OptionalHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG)pDosHeader + pOptionHeader->DataDirectory[1].VirtualAddress);

		
	// 遍历INT表
	while (pImportTable->OriginalFirstThunk || pImportTable->FirstThunk)
	{
		// 在里面定义，变量的值每次都会重新设置为空

		//模块基址
		PVOID pModuleBase = NULL;
		// 模块名字
		CHAR szName[0x50] = { 0 };
		ANSI_STRING asName = { 0 };
		UNICODE_STRING usName = { 0 };


		// 获取模块名,由模块名字获取模块基址
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

		// 获取模块基址
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

		// 修复IAT表

		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((ULONG)pKernelImageBuffer + pImportTable->FirstThunk);

		while (*((PULONG)pThunkData) != 0)
		{
			EXP_FUN_NAME emFunName = { 0 };
			ULONG dwProcAddress = 0;

			//__asm int 3;
			// IMAGE_THUNK_DATA32 是一个4字节数据
			// 如果最高位是1，那么除去最高位就是导出序号
			// 如果最高位是0，那么这个值是RVA 指向 IMAGE_IMPORT_BY_NAME
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

				// 按名字导入

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
	//新内核地址-老内核地址，得到相对偏移
	ULONG uNewKernelInc = (ULONG)pKernelImageBuffer - uKernelOldBase;

	//DbgPrint("KeServiceDescriptorTable: [%X]\r\n", KeServiceDescriptorTable);
	//DbgPrint("pKernelImageBuffer: [%X]\r\n", pKernelImageBuffer);
	//DbgPrint("uKernelOldBase: [%X]\r\n", uKernelOldBase);
	//DbgPrint("uNewKernelInc: [%X]\r\n", uNewKernelInc);
	// __asm int 3;


	//老内核的ssdt指针加上相对偏移，得到新内核的ssdt指针

	PKSYSTEM_SERVICE_TABLE pNewSSDT = (PKSYSTEM_SERVICE_TABLE)((ULONG)KeServiceDescriptorTable + uNewKernelInc);


	if (!MmIsAddressValid(pNewSSDT))
	{
		DbgPrint("pNewSSDT is unaviable!\r\n");
		return;
	}


	// 修正新的 SSDT 成员

	// 函数地址表
	pNewSSDT->ServiceTableBase = (PULONG)((ULONG)pKernelImageBuffer + (ULONG)(KeServiceDescriptorTable->ServiceTableBase) - uKernelOldBase );

	// 依次遍历修改
	for (ULONG uIndex = 0; uIndex < KeServiceDescriptorTable->NumberOfServices; uIndex++)
	{
		// 这里碰到了一个坑，我怀疑是修复重定位时的坑——————在执行修复重定位的代码前下了断点，查看了一下，8成的可能性。
		// pNewSSDT->ServiceTableBase[uIndex] += uNewKernelInc;
		// 函数地址再加上相对加载地址，得到新的的ssdt函数地址------这样写就不怕重定位代码问题了。
		pNewSSDT->ServiceTableBase[uIndex] = KeServiceDescriptorTable->ServiceTableBase[uIndex] + uNewKernelInc;
	}

	if (!MmIsAddressValid(pNewSSDT->ServiceTableBase))
	{
		DbgPrint("pNewSSDT->ServiceTableBase: %X\r\n", pNewSSDT->ServiceTableBase);
		return;
	}

	// 函数数量
	pNewSSDT->NumberOfServices = KeServiceDescriptorTable->NumberOfServices;

	// 计算相对函数参数地址表的偏移
	ULONG uOffset2 = (ULONG)KeServiceDescriptorTable->ParamTableBase - uKernelOldBase;
	
	// 函数参数表
	pNewSSDT->ParamTableBase = (PULONG)((ULONG)pKernelImageBuffer + uOffset2);

	//DbgPrint("pNewSSDT->ServiceTableBase: %X\r\n", pNewSSDT->ServiceTableBase);
	//DbgPrint("pNewSSDT->NumberOfServices: %X\r\n", pNewSSDT->NumberOfServices);
	//DbgPrint("pNewSSDT->ParamTableBase: %X\r\n", pNewSSDT->ParamTableBase);

	//__asm int 3;
	return pNewSSDT;
}



// 关闭内存页写入保护
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

// 开启内存页写入保护
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


	// 找到KiFastCallEntry函数首地址
	ULONG uKiFastCallEntry = 0;
	_asm
	{
		;// KiFastCallEntry函数地址保存
		;// 在特殊模组寄存器的0x176号寄存器中
		pushad;
		mov ecx, 0x176; // 设置编号
		rdmsr; ;// 读取到edx:eax
		mov uKiFastCallEntry, eax;// 保存到变量
		popad;
	}


	// 找到HOOK的位置, 并保存5字节的数据
	// 1 HOOK的位置选定为(此处正好5字节,):
	//  2be1           sub     esp, ecx ;
	//  c1e902         shr     ecx, 2   ;
	UCHAR hookCode[5] = { 0x2b,0xe1,0xc1,0xe9,0x02 }; //保存inline hook覆盖的5字节

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
		DbgPrint("在KiFastCallEntry函数中没有找到HOOK位置,可能KiFastCallEntry已经被HOOK过了\n");
		
		return;
	}

	g_hookAddr = uKiFastCallEntry + i;
	g_hookAddr_next_ins = g_hookAddr + 5;


	// 开始inline hook
	UCHAR jmpCode[5] = { 0xe9 };// jmp xxxx

	//__asm int 3;

	disablePageWriteProtect();

	// 1 计算跳转偏移
	// 跳转偏移 = 目标地址 - 当前地址 - 5
	*(ULONG*)(jmpCode + 1) = (ULONG)myKiFastEntryHook - g_hookAddr - 5;


	// 2 将跳转指令写入
	RtlCopyMemory(uKiFastCallEntry + i, jmpCode, 5);
	enablePageWriteProtect();
	//__asm int 3;
}

ULONG SSDTFilter(ULONG index, ULONG tableAddress, PULONG funAddr)
{
	
	//DbgPrint("index:[%X],tableAddress:[%X],funAddr:[%X]\t\n", index, tableAddress, funAddr);
	//__asm int 3;
	// 如果是SSDT表的话
	if (tableAddress == KeServiceDescriptorTable->ServiceTableBase)
	{
		
		// 判断调用号(0x&A是ZwOpenProcess函数的调用号)
		if (index == 0x7A)
		{
			// 返回新SSDT表的函数地址
			// 也就是新内核的函数地址
			DbgPrint("New\t\n");
			return pNewSSDT->ServiceTableBase[0x7A];
		}
	}
	// 返回旧的函数地址
	return funAddr;
}

void _declspec(naked) myKiFastEntryHook()
{
	_asm
	{
		pushad; // 压栈寄存器: eax,ecx,edx,ebx, esp,ebp ,esi, edi
		pushfd; // 压栈标志寄存器


		push edx; // 从表中取出的函数地址
		push edi; // 表的地址
		push eax; // 调用号
		call SSDTFilter; // 调用过滤函数


		;// 函数调用完毕之后栈控件布局,指令pushad将
		;// 32位的通用寄存器保存在栈中,栈空间布局为:
		;// [esp + 00] <=> eflag
		;// [esp + 04] <=> edi
		;// [esp + 08] <=> esi
		;// [esp + 0C] <=> ebp
		;// [esp + 10] <=> esp
		;// [esp + 14] <=> ebx
		;// [esp + 18] <=> edx <<-- 使用函数返回值来修改这个位置
		;// [esp + 1C] <=> ecx
		;// [esp + 20] <=> eax
		mov dword ptr ds : [esp + 0x18] , eax;
		popfd; // popfd时,实际上edx的值就会被修改
		popad;

		; //执行被hook覆盖的两条指令
		sub esp, ecx;
		shr ecx, 2;
		jmp g_hookAddr_next_ins;
	}
}
// https://dennisbabkin.com/blog/?t=how-to-implement-getprocaddress-in-shellcode
#include <Windows.h>

#if _WIN64
inline uintptr_t GetKernel32Base()
{
	uintptr_t Peb = __readgsqword(0x60);
	uintptr_t Ldr = *(uintptr_t*)(Peb + 0x18);
	uintptr_t InMemoryOrderModuleList = *(uintptr_t*)(Ldr + 0x20);
	uintptr_t Ntdll = *(uintptr_t*)(InMemoryOrderModuleList);
	uintptr_t Kernel32 = *(uintptr_t*)(Ntdll);
	uintptr_t Kernel32Base = *(uintptr_t*)(Kernel32 + 0x20);
	return Kernel32Base;
}
#else

inline uintptr_t GetKernel32Base()
{
	uintptr_t Peb = __readfsdword(0x30);
	uintptr_t Ldr = *(uintptr_t*)(Peb + 0xC);
	uintptr_t InMemoryOrderModuleList = *(uintptr_t*)(Ldr + 0x14);
	uintptr_t Ntdll = *(uintptr_t*)(InMemoryOrderModuleList);
	uintptr_t Kernel32 = *(uintptr_t*)(Ntdll);
	uintptr_t Kernel32Base = *(uintptr_t*)(Kernel32 + 0x10);
	return Kernel32Base;
}
#endif

#if _WIN64
inline uintptr_t GetAddrGetProcAddress(uintptr_t Kernel32)
{
	IMAGE_DOS_HEADER* K32 = (IMAGE_DOS_HEADER*)Kernel32;

	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(Kernel32 + K32->e_lfanew);
	IMAGE_OPTIONAL_HEADER* optHeaders = &ntHeaders->OptionalHeader;
	IMAGE_DATA_DIRECTORY* dataDirectory = optHeaders->DataDirectory;
	IMAGE_DATA_DIRECTORY* dataDirectoryEntryExport = &dataDirectory[0];
	IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(Kernel32 + dataDirectoryEntryExport->VirtualAddress);

	uintptr_t names = (Kernel32 + exportDirectory->AddressOfNames);


	DWORD* NameRva = (DWORD*)names;
	uintptr_t name = NULL;

	uintptr_t GetProcA = 0x41636f7250746547;
	uintptr_t Adress0 = 0x0073736572646441;

	int idx = -1;

	for (int i = 0; i < exportDirectory->NumberOfNames; i++)
	{
		name = *(uintptr_t*)(Kernel32 + *NameRva);

		if (name == GetProcA)
		{
			name = *(uintptr_t*)((Kernel32 + *NameRva) + 7);
			if (name == Adress0)
			{
				idx = i;
			}
		}

		NameRva++;
	}

	if (idx <= 0)
	{
		return 0;
	}

	WORD* ordinals = (WORD*)(Kernel32 + exportDirectory->AddressOfNameOrdinals);

	WORD ordinal = ordinals[idx];

	DWORD* exportAddressTable = (DWORD*)(Kernel32 + exportDirectory->AddressOfFunctions);

	DWORD funcRva = exportAddressTable[ordinal];

	uintptr_t func = (uintptr_t)(Kernel32 + funcRva);

	return func;
}
#else
inline uintptr_t GetAddrGetProcAddress()
{
	return 0;
}
#endif

extern "C" uintptr_t _code()
{

	uintptr_t Kernel32 = GetKernel32Base();
	uintptr_t pGetProcAddress = GetAddrGetProcAddress(Kernel32);

	typedef FARPROC(WINAPI* funcGPA)(uintptr_t, char*);
	funcGPA GetProcAddress = (funcGPA)pGetProcAddress;

	const char strLoadLibrary[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\x00' };

	uintptr_t pLoadLibraryA = (uintptr_t)GetProcAddress(Kernel32, (char*)strLoadLibrary);

	typedef uintptr_t(WINAPI* funcLLA)(char*);
	funcLLA LoadLibraryA = (funcLLA)pLoadLibraryA;


	char strUser32[] = { 'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\x00' };

	uintptr_t User32 = LoadLibraryA(strUser32);

	char strMessageBox[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', '\x00' };

	uintptr_t pMessageBox = (uintptr_t)GetProcAddress(User32, strMessageBox);

	char strMsg[] = { 'G', 'e', 't', ' ', 'H', 'a', 'c', 'k', 'e', 'd', '\x00' };

	typedef int (WINAPI* funcMBA)(HWND, LPCSTR, LPCSTR, UINT);
	funcMBA MessageBoxA = (funcMBA)pMessageBox;
	MessageBoxA(0, strMsg, 0, 0);

	return pLoadLibraryA;
}


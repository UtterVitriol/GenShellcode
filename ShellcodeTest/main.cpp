#include <Windows.h>
#include <iostream>


unsigned char data[336] = {
	0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83,
	0xEC, 0x60, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x33, 0xFF, 0x41, 0xB8, 0xFF,
	0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0x48, 0x18, 0x48, 0x8B, 0x41, 0x20, 0x48, 0x8B, 0x08, 0x48, 0x8B,
	0x01, 0x8B, 0xCF, 0x4C, 0x8B, 0x48, 0x20, 0x49, 0x63, 0x41, 0x3C, 0x46, 0x8B, 0x9C, 0x08, 0x88,
	0x00, 0x00, 0x00, 0x4D, 0x03, 0xD9, 0x41, 0x8B, 0x53, 0x20, 0x45, 0x8B, 0x53, 0x18, 0x49, 0x03,
	0xD1, 0x45, 0x85, 0xD2, 0x74, 0x5D, 0x48, 0x89, 0x74, 0x24, 0x70, 0x48, 0xBB, 0x47, 0x65, 0x74,
	0x50, 0x72, 0x6F, 0x63, 0x41, 0x48, 0xBE, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x00, 0x90,
	0x8B, 0x02, 0x4A, 0x39, 0x1C, 0x08, 0x75, 0x09, 0x4A, 0x39, 0x74, 0x08, 0x07, 0x44, 0x0F, 0x44,
	0xC1, 0x48, 0x83, 0xC2, 0x04, 0xFF, 0xC1, 0x41, 0x3B, 0xCA, 0x72, 0xE4, 0x48, 0x8B, 0x74, 0x24,
	0x70, 0x45, 0x85, 0xC0, 0x7E, 0x1D, 0x41, 0x8B, 0x4B, 0x24, 0x49, 0x03, 0xC9, 0x49, 0x63, 0xD0,
	0x44, 0x0F, 0xB7, 0x04, 0x51, 0x41, 0x8B, 0x4B, 0x1C, 0x49, 0x03, 0xC9, 0x42, 0x8B, 0x3C, 0x81,
	0x49, 0x03, 0xF9, 0x48, 0x8D, 0x55, 0xF0, 0xC7, 0x45, 0xF0, 0x4C, 0x6F, 0x61, 0x64, 0x49, 0x8B,
	0xC9, 0xC7, 0x45, 0xF4, 0x4C, 0x69, 0x62, 0x72, 0xC7, 0x45, 0xF8, 0x61, 0x72, 0x79, 0x41, 0xC6,
	0x45, 0xFC, 0x00, 0xFF, 0xD7, 0x48, 0x8B, 0xD8, 0xC7, 0x45, 0xC0, 0x55, 0x73, 0x65, 0x72, 0x48,
	0x8D, 0x4D, 0xC0, 0xC7, 0x45, 0xC4, 0x33, 0x32, 0x2E, 0x64, 0x66, 0xC7, 0x45, 0xC8, 0x6C, 0x6C,
	0xC6, 0x45, 0xCA, 0x00, 0xFF, 0xD3, 0x48, 0x8D, 0x55, 0xE0, 0xC7, 0x45, 0xE0, 0x4D, 0x65, 0x73,
	0x73, 0x48, 0x8B, 0xC8, 0xC7, 0x45, 0xE4, 0x61, 0x67, 0x65, 0x42, 0xC7, 0x45, 0xE8, 0x6F, 0x78,
	0x41, 0x00, 0xFF, 0xD7, 0x45, 0x33, 0xC9, 0xC7, 0x45, 0xD0, 0x47, 0x65, 0x74, 0x20, 0x45, 0x33,
	0xC0, 0xC7, 0x45, 0xD4, 0x48, 0x61, 0x63, 0x6B, 0x48, 0x8D, 0x55, 0xD0, 0x66, 0xC7, 0x45, 0xD8,
	0x65, 0x64, 0x33, 0xC9, 0xC6, 0x45, 0xDA, 0x00, 0xFF, 0xD0, 0x48, 0x8B, 0xBC, 0x24, 0x80, 0x00,
	0x00, 0x00, 0x48, 0x8B, 0xC3, 0x48, 0x8B, 0x5C, 0x24, 0x78, 0x48, 0x83, 0xC4, 0x60, 0x5D, 0xC3
};

int main()
{
	DWORD dwOld = 0;
	PBYTE exec = (PBYTE)VirtualAlloc(0, sizeof(data), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!exec)
	{
		puts("VirtualAlloc");
	}

	memcpy(exec, data, sizeof(data));


	uintptr_t ree = 0;
	ree = ((uintptr_t(*)())exec)();

	HMODULE k = LoadLibraryA("Kernel32.dll");
	uintptr_t g = (uintptr_t)GetProcAddress(k, "LoadLibraryA");

	printf("Output: %p\n", ree);
	printf("Result: %p\n", g);
}
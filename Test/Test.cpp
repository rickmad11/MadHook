#if defined(_DEBUG) && defined(_M_X64)
#pragma comment(lib, "../x64/Debug/MadHook.lib")
#elif defined(_M_X64)
#pragma comment(lib, "../x64/Release/MadHook.lib")
#endif

#if defined(_DEBUG) && !defined(_M_X64)
#pragma comment(lib, "../Debug/MadHook.lib")
#elif !defined(_M_X64)
#pragma comment(lib, "../Release/MadHook.lib")
#endif

#include <windows.h>
#include <iostream>
#include "../src/MadHook/MadHook.hpp"

#ifdef _M_X64
static BYTE ___asm_test_function2[]
{
	0xE9, 0x05, 0x00, 0x00, 0x00,
	0x90, 0x90, 0x90, 0x90, 0x90,
	0x48, 0xC7, 0x01, 0x0A, 0x00, 0x00, 0x00,
	0xC3,
};

static BYTE ___asm_test_function3[]
{
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0x01, 0x0A, 0x00, 0x00, 0x00,
	0xC3,
};

#else
static BYTE ___asm_test_function2[]
{
	0xE9, 0x05, 0x00, 0x00, 0x00,
	0x90, 0x90, 0x90, 0x90, 0x90,
	0xC7, 0x00, 0x0A, 0x00, 0x00, 0x00,
	0xC3,
};

static BYTE ___asm_test_function3[]
{
	0xFF, 0x25, 0x04, 0x00, 0x00, 0x00,
	0xC3,
};
void* gp_test_asm_function3 = &___asm_test_function3[6];
#endif

void SetupTestAsm()
{
	DWORD dummy;
	VirtualProtect(&___asm_test_function2, 1, PAGE_EXECUTE_READWRITE, &dummy);

	VirtualProtect(&___asm_test_function3, 1, PAGE_EXECUTE_READWRITE, &dummy);

#ifdef _M_X64
	*reinterpret_cast<DWORD64**>(&___asm_test_function3[6]) = reinterpret_cast<DWORD64*>(&___asm_test_function3[14]);
#else
	*reinterpret_cast<DWORD64**>(&___asm_test_function3[2]) = reinterpret_cast<DWORD64*>(&gp_test_asm_function3);
#endif
}

#pragma optimize( "", off )
DWORD test_function1(int arg1, void* arg2)
{
	//printf("value1: %i   value2: %p\n", arg1, arg2);
	return arg1;
}

int __fastcall test_function2(int arg1)
{
	reinterpret_cast<void(*)(void*)>(&___asm_test_function2)(&arg1);

	return arg1;
}

int __fastcall test_function3(int arg1)
{
	reinterpret_cast<void(*)(void*)>(&___asm_test_function3)(&arg1);

	return arg1;
}
#pragma optimize( "", on )


struct TESTCLASS
{
	DWORD test_member1(DWORD arg1)
	{
		//printf("value1: %i \n", arg1);
		return arg1;
	}
};

namespace Hooked
{
	decltype(MessageBoxA)* pfMessageBoxA = nullptr;
	static int WINAPI MessageBoxA(HWND a1, LPCSTR a2, LPCSTR a3, UINT a4)
	{
		//MessageBoxW(nullptr, L"HOOKED MessageBoxA", L"HOOKED", 0);
		printf("MessageBoxA arg1: %p  arg2: %s  arg3: %s arg4: %u \n", a1, a2, a3, a4);
		return pfMessageBoxA(a1, a2, a3, a4);
	}

	decltype(test_function1)* pfTest1 = nullptr;
	DWORD test_function1(int arg1, void* arg2)
	{
		printf("test_function1: value1: %i   value2: %p\n", arg1, arg2);
		return pfTest1(arg1, arg2);
	}

	decltype(test_function2)* pfTest2 = nullptr;
	int test_function2(int arg1)
	{
		printf("test_function2 value1: %i\n", arg1);
		return pfTest2(arg1);
	}

	decltype(test_function3)* pfTest3 = nullptr;
	int test_function3(int arg1)
	{
		printf("test_function3 value1: %i\n", arg1);
		return pfTest3(arg1);
	}

	DWORD(__thiscall* pfMemberTest1)(void*, DWORD) = nullptr;
#ifdef _M_X64
	DWORD test_member_function1(void* _this, DWORD arg1)
	{
		arg1 = 0;
		printf("value1: %i \n", arg1);
		return pfMemberTest1(_this, arg1);
	}
#else
	DWORD __fastcall test_member_function1(void* _this, void* edx, DWORD arg1)
	{
		arg1 = 0;
		printf("value1: %i \n", arg1);
		return pfMemberTest1(_this, arg1);
	}
#endif

	decltype(WriteProcessMemory)* pfWriteProcessMemory = nullptr;
	BOOL WINAPI WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
	{
		printf("Handle: %p   BaseAddress: %p  Size: %u \n", hProcess, lpBaseAddress, nSize);
		return pfWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}

	decltype(GetCurrentThreadId)* pfGetCurrentThreadId = nullptr;
	DWORD GetCurrentThreadId()
	{
		//printf("Current Thread Id: %u \n", pfGetCurrentThreadId());
		return pfGetCurrentThreadId();
	}

	decltype(BitBlt)* pfBitBlt = nullptr;
	BOOL WINAPI BitBlt(_In_ HDC hdc, _In_ int x, _In_ int y, _In_ int cx, _In_ int cy, _In_opt_ HDC hdcSrc, _In_ int x1, _In_ int y1, _In_ DWORD rop)
	{
		printf("hdc: %p, x: %d, y: %d, cx: %d, cy: %d, hdcSrc: %p, x1: %d, y1: %d, rop: %lu\n", hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
		return pfBitBlt(hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
	}

	decltype(TlsAlloc)* pfTlsAlloc = nullptr;
	DWORD WINAPI TlsAlloc(VOID)
	{
		DWORD return_value = pfTlsAlloc();
		//printf("TlsAlloc returned: %u\n", return_value);
		return return_value;
	}

	decltype(GetProcAddress)* pfGetProcAddress = nullptr;
	FARPROC WINAPI GetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName)
	{
		//if((std::uintptr_t)lpProcName >> 16)
		//	printf("GetProcAddress arg1: %p arg2: %s\n", hModule, lpProcName);
		return pfGetProcAddress(hModule, lpProcName);
	}

	void* pfNtSetInformationFile = nullptr;
	NTSTATUS WINAPI NtSetInformationFile(HANDLE FileHandle, void* IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass)
	{
		printf("FileHandle: %p, IoStatusBlock: %p, FileInformation: %p, Length: %lu, FileInformationClass: %d\n", FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
		return reinterpret_cast<decltype(NtSetInformationFile)*>(pfNtSetInformationFile)(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	}
}

int main()
{
	SetupTestAsm();

	if (MadHook::Initialize() != MadHook::Status::MH_OK)
		std::cout << "Failure on Initialize \n";

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");

	//windows api functions
	MadHook::CreateHook(MessageBoxA, Hooked::MessageBoxA, (void**)&Hooked::pfMessageBoxA);
	MadHook::CreateHook(WriteProcessMemory, Hooked::WriteProcessMemory, (void**)&Hooked::pfWriteProcessMemory);
	MadHook::CreateHook(GetProcAddress(kernelbase, "TlsAlloc"), Hooked::TlsAlloc, (void**)&Hooked::pfTlsAlloc);
	MadHook::CreateHook(BitBlt, Hooked::BitBlt, (void**)&Hooked::pfBitBlt);
	MadHook::CreateHook(GetProcAddress(kernelbase, "GetProcAddress"), Hooked::GetProcAddress, (void**)&Hooked::pfGetProcAddress);
	MadHook::CreateHook(GetProcAddress(ntdll, "NtSetInformationFile"), Hooked::NtSetInformationFile, (void**)&Hooked::pfNtSetInformationFile);

	//Works but don't use while debugging bcs of calls to __CheckForDebuggerJustMyCode which causes infinite recursion
	//MadHook::CreateHook(GetCurrentThreadId, Hooked::GetCurrentThreadId, (void**)&Hooked::pfGetCurrentThreadId);

	//own functions
	MadHook::CreateHook(test_function1, Hooked::test_function1, (void**)&Hooked::pfTest1);
	MadHook::CreateHook(test_function2, Hooked::test_function2, (void**)&Hooked::pfTest2);
	MadHook::CreateHook(test_function3, Hooked::test_function3, (void**)&Hooked::pfTest3);
	
	//class member functions
	DWORD(__thiscall TESTCLASS:: * pfMember1)(DWORD) = &TESTCLASS::test_member1;
	MadHook::CreateHook((void*&)pfMember1, Hooked::test_member_function1, (void**)&Hooked::pfMemberTest1);

	MadHook::EnableAllHooks();

	{
		//windows api functions
		MessageBoxA(nullptr, "text", "text", 0);
		WriteProcessMemory((HANDLE)-1, nullptr, nullptr, 10, nullptr);
		GetCurrentThreadId();
		BitBlt(nullptr, 0, 0, 0, 0, nullptr, 89, 500, 0);
		TlsAlloc();
		reinterpret_cast<decltype(Hooked::NtSetInformationFile)*>(GetProcAddress(ntdll, "NtSetInformationFile"))(nullptr, nullptr, nullptr, 10, 10);

		//own functions
		test_function1(10, (void*)0xDEADBEEF);
		test_function2(0);
		test_function3(5000);

		//class member functions
		TESTCLASS test_class;
		test_class.test_member1(10);

	}

	MadHook::DisableAllHooks();

	{
		//windows api functions
		MessageBoxA(nullptr, "text", "text", 0);
		WriteProcessMemory((HANDLE)-1, nullptr, nullptr, 10, nullptr);
		GetCurrentThreadId();
		BitBlt(nullptr, 0, 0, 0, 0, nullptr, 89, 500, 0);

		//own functions
		test_function1(10, (void*)0xDEADBEEF);
		test_function2(0);
		test_function3(1);

		//class member functions
		TESTCLASS test_class;
		test_class.test_member1(10);

	}

	if (MadHook::UnInitialize() != MadHook::Status::MH_OK)
		std::cout << "Failure on UnInitialize";
}
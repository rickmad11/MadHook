#include "pch.h"

#include "Syscalls.hpp"
#include "WinFunctions.hpp"
#include "MadHook/MadHook.hpp"
#include "MemoryManager/MemoryManager.hpp"

namespace MadSyscall::Global
{
	namespace //so I don't have to specify static all the time
	{
		namespace Address
		{
			BYTE* ntdll = nullptr;

			MemoryManager::PLIST_ENTRY indirect_syscall_entry = nullptr;
			MemoryManager::PLIST_ENTRY direct_syscall_entry = nullptr;
		}

#ifdef _M_X64
		BYTE indirect_syscall_asm[] =
		{
			0x4C, 0x8B, 0xD1,								//mov r10, rcx
			0xB8, 0x00, 0x00, 0x00, 0x00,					//mov eax, syscall_id
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,				//jmp qword ptr [null offset]
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //8 byte jump target address
		};

		BYTE direct_syscall_asm[] =
		{
			0x4C, 0x8B, 0xD1,								//mov r10, rcx
			0xB8, 0x00, 0x00, 0x00, 0x00,					//mov eax, syscall_id
			0x0F, 0x05,										//syscall
			0xC3,											//retn
		};
#else
		//BYTE indirect_syscall_asmX86[] =
		//{
		//	0xB8, 0x00, 0x00, 0x00, 0x00,
		//	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, //<- runtime wow64cpu.dll + 7000 or Wow64SystemServiceCall() just adjust return value according
		//};

		BYTE direct_syscall_asmX86[] =
		{
			0xB8, 0x00, 0x00, 0x00, 0x00,
			0xBA, 0x00, 0x00, 0x00, 0x00, // <- needs to be set runtime to Wow64SystemServiceCall()
			0xFF, 0xD2,
			0xC2, 0x00, 0x00 //<- needs to be set runtime to return value
		};
#endif
	}
}

namespace MadSyscall
{
	MadHook::Status Initialize()
	{
		if (Global::Address::ntdll = reinterpret_cast<BYTE*>(GetModuleAddress(L"ntdll.dll")); !Global::Address::ntdll)
			return MadHook::Status::MS_FAILURE_ON_ADDRESS_RESOLVING;

		BYTE* pAllocation = nullptr;
		ULONG_PTR region_size = 1;

		reinterpret_cast<NTSTATUS(WINAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(GetFunctionAddress("NtAllocateVirtualMemory"))
		((HANDLE)-1, reinterpret_cast<PVOID*>(&pAllocation), NULL, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

#ifdef _M_X64
		//if (!MemoryManager::Insert(typeid(Global::indirect_syscall_asm), Global::indirect_syscall_asm, sizeof(Global::indirect_syscall_asm)))
		//	return MadHook::Status::MS_FAILURE;
		//
		//if (!MemoryManager::Insert(typeid(Global::direct_syscall_asm), Global::direct_syscall_asm, sizeof(Global::direct_syscall_asm)))
		//	return MadHook::Status::MS_FAILURE;

		memcpy_s(pAllocation, 1 << 12, Global::direct_syscall_asm, sizeof(Global::direct_syscall_asm));
		memcpy_s(pAllocation + sizeof(Global::direct_syscall_asm), 1 << 12, Global::indirect_syscall_asm, sizeof(Global::indirect_syscall_asm));

		Global::Address::direct_syscall_entry   = reinterpret_cast<MemoryManager::PLIST_ENTRY>(pAllocation);
		Global::Address::indirect_syscall_entry = reinterpret_cast<MemoryManager::PLIST_ENTRY>(pAllocation + sizeof(Global::direct_syscall_asm));

		//BYTE d_cmpVaule = 0x0F;
		//Global::Address::direct_syscall_entry = MemoryManager::GetEntry(typeid(Global::direct_syscall_asm), 0x8, &d_cmpVaule, sizeof(d_cmpVaule));
		//
		//BYTE i_cmpVaule = 0xFF;
		//Global::Address::indirect_syscall_entry = MemoryManager::GetEntry(typeid(Global::indirect_syscall_asm), 0x8, &i_cmpVaule, sizeof(i_cmpVaule));

		if (!Global::Address::indirect_syscall_entry || !Global::Address::direct_syscall_entry)
			return MadHook::Status::MS_FAILURE;

#else
		//if (!MemoryManager::Insert(typeid(Global::direct_syscall_asmX86), Global::direct_syscall_asmX86, sizeof(Global::direct_syscall_asmX86)))
		//	return MadHook::Status::MS_FAILURE;
		//
		//BYTE d_cmpVaule = 0xBA;
		//Global::Address::direct_syscall_entry = MemoryManager::GetEntry(typeid(Global::direct_syscall_asmX86), 0x5, &d_cmpVaule, sizeof(d_cmpVaule));

		memcpy_s(pAllocation, 1 << 12, Global::direct_syscall_asmX86, sizeof(Global::direct_syscall_asmX86));
		Global::Address::direct_syscall_entry = reinterpret_cast<MemoryManager::PLIST_ENTRY>(pAllocation);

		if (!Global::Address::direct_syscall_entry)
			return MadHook::Status::MS_FAILURE;
#endif

		return MadHook::Status::MS_OK;
	}

	void* GetModuleAddress(std::wstring_view module_name)
	{
		PLIST_ENTRY p_list_entry_head = &reinterpret_cast<PTEB>(NtCurrentTeb())->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;

		for (PLIST_ENTRY curr = p_list_entry_head->Flink; curr && curr != p_list_entry_head; curr = curr->Flink)
		{
			PLDR_DATA_TABLE_ENTRY p_ldr_data_table_entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if(module_name.empty())
				return p_ldr_data_table_entry->DllBase;

			if (!wcscmp(reinterpret_cast<wchar_t const*>(p_ldr_data_table_entry->BaseDllName.Buffer), module_name.data()))
				return p_ldr_data_table_entry->DllBase;
		}

		return nullptr;
	}

	void* GetFunctionAddress(std::string_view function_name)
	{
		BYTE* module_base = Global::Address::ntdll;

		PIMAGE_DOS_HEADER p_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
		PIMAGE_NT_HEADERS p_nt_header  = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base + p_dos_header->e_lfanew);

		PIMAGE_EXPORT_DIRECTORY p_export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + module_base);

		DWORD* function_name_array		 = reinterpret_cast<DWORD*>(p_export_dir->AddressOfNames + module_base);
		DWORD* function_address_array	 = reinterpret_cast<DWORD*>(p_export_dir->AddressOfFunctions + module_base);
		WORD* ordinal_array				 = reinterpret_cast<WORD*>(p_export_dir->AddressOfNameOrdinals + module_base);

		for (std::size_t index = 0; index < p_export_dir->NumberOfNames; ++index)
		{
			if(!std::strcmp(reinterpret_cast<const char*>(function_name_array[index] + module_base), function_name.data()))
				return (function_address_array[ordinal_array[index]] + module_base);
		}

		return nullptr;
	}

	static BYTE* PrepareShellcodeX86(BYTE* const address_of_function)
	{
		const DWORD syscall_id = *reinterpret_cast<DWORD*>(address_of_function + 1);
		const SHORT ret_value  = *reinterpret_cast<SHORT*>(address_of_function + 13);

		BYTE* const direct_syscall_asm = reinterpret_cast<BYTE* const>(Global::Address::direct_syscall_entry);

		*reinterpret_cast<DWORD*>(direct_syscall_asm + 1) = syscall_id;
		*reinterpret_cast<DWORD*>(direct_syscall_asm + 6) = *reinterpret_cast<DWORD*>(address_of_function + 6);
		*reinterpret_cast<SHORT*>(direct_syscall_asm + 13) = ret_value;

		return direct_syscall_asm;
	}

	BYTE* PrepareShellcode(BYTE* const address_of_function, bool direct)
	{
#ifdef _M_X64
		const DWORD syscall_id = *reinterpret_cast<DWORD*>(address_of_function + 4);

		if(direct)
		{
			BYTE* const direct_syscall_asm = reinterpret_cast<BYTE* const>(Global::Address::direct_syscall_entry);

			*reinterpret_cast<DWORD*>(direct_syscall_asm + 4) = syscall_id;

			return direct_syscall_asm;
		}

		BYTE* const indirect_syscall_asm = reinterpret_cast<BYTE* const>(Global::Address::indirect_syscall_entry);

		*reinterpret_cast<DWORD*>(indirect_syscall_asm + 4) = syscall_id;
		*reinterpret_cast<DWORD64**>(indirect_syscall_asm + 14) = reinterpret_cast<DWORD64*>(address_of_function + 18);

		return indirect_syscall_asm;

#else
		return PrepareShellcodeX86(address_of_function);
#endif
	}

}
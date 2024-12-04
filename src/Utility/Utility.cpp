#include "pch.h"
#include "Utility.hpp"

#include "MadSyscalls/Syscalls.hpp"

namespace Utility
{
	std::size_t GetFunctionSize(BYTE const* pTargetFunction)
	{
		MEMORY_BASIC_INFORMATION mbi{};

		(void)MadSyscall::Indirect::Invoke<NTSTATUS>("NtQueryVirtualMemory", (HANDLE)-1,
			pTargetFunction, WinTypes::MemoryBasicInformation,
			&mbi, sizeof(mbi), nullptr);

		if (mbi.State == MEM_FREE || mbi.State == MEM_RESERVE && mbi.AllocationBase == nullptr)
			return 0;

		ZydisDecoder decoder{};
		ZydisDecodedInstruction decoded_instruction{};
		ZydisDecodedOperand decoded_operand[ZYDIS_MAX_OPERAND_COUNT];

#ifdef _M_X64 
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#endif

		std::size_t function_size = 0;

		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, pTargetFunction, ZYDIS_MAX_INSTRUCTION_LENGTH, &decoded_instruction, decoded_operand)))
		{
			function_size += decoded_instruction.length;
			pTargetFunction += decoded_instruction.length;

			if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_RET)
				return function_size;

			if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_INT3)
				return function_size;

			(void)MadSyscall::Indirect::Invoke<NTSTATUS>("NtQueryVirtualMemory", (HANDLE)-1,
				pTargetFunction + ZYDIS_MAX_INSTRUCTION_LENGTH, WinTypes::MemoryBasicInformation,
				&mbi, sizeof(mbi), nullptr);

			if (mbi.State == MEM_FREE || mbi.State == MEM_RESERVE && mbi.AllocationBase == nullptr)
				return 0;
		}

		return 0;
	}

	void* FindCloseMemory(BYTE const* const pTargetFunction, std::size_t dwAllocationGranularity)
	{
		std::size_t search_range = ZYAN_ALIGN_DOWN(2147483648, dwAllocationGranularity); // ~2 GB

		BYTE const* pStartRange = pTargetFunction - search_range;
		BYTE const* pEndRange = pTargetFunction + search_range;

		pStartRange = reinterpret_cast<BYTE const*>(ZYAN_ALIGN_UP(reinterpret_cast<std::uintptr_t>(pStartRange), dwAllocationGranularity));
		pEndRange = reinterpret_cast<BYTE const*>(ZYAN_ALIGN_DOWN(reinterpret_cast<std::uintptr_t>(pEndRange), dwAllocationGranularity));

		//std::uint64_t page_count = (reinterpret_cast<std::uintptr_t>(pEndRange) - reinterpret_cast<std::uintptr_t>(pStartRange)) / dwAllocationGranularity;

		MEMORY_BASIC_INFORMATION mbi{};
		for (BYTE const* pCurrentAddr = pStartRange; pCurrentAddr < pEndRange;)
		{
			NTSTATUS status = MadSyscall::Indirect::Invoke<NTSTATUS>("NtQueryVirtualMemory", (HANDLE)-1,
				pCurrentAddr, WinTypes::MemoryBasicInformation,
				&mbi, sizeof(mbi), nullptr);

			if (status < 0)
				break;

			if (mbi.State == MEM_FREE)
				return const_cast<void*>(reinterpret_cast<void const*>(pCurrentAddr));

			pCurrentAddr = reinterpret_cast<BYTE const*>(reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize);
			pCurrentAddr = reinterpret_cast<BYTE const*>(ZYAN_ALIGN_UP(reinterpret_cast<std::uintptr_t>(pCurrentAddr), dwAllocationGranularity));
		}

		return nullptr;
	}

	NTSTATUS ChangePageProtection(PVOID BaseAddress, ULONG NewAccessProtection, PULONG OldAccessProtection)
	{
		SIZE_T page_size = 1;

		return MadSyscall::Indirect::Invoke<NTSTATUS>("NtProtectVirtualMemory", (HANDLE)-1,
			&BaseAddress, &page_size,
			NewAccessProtection, OldAccessProtection);
	}
}
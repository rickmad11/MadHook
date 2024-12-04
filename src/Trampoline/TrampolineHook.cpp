#include "pch.h"
#include "TrampolineHook.hpp"

#include "MadSyscalls/Syscalls.hpp"
#include "MemoryManager/MemoryManager.hpp"
#include "ThreadManager/ThreadManager.hpp"
#include "Utility/Utility.hpp"

struct TrampolineHookData
{
	void* pTargetFunction = nullptr;
	void* Gateway = nullptr;
	void* pDetourFunction = nullptr;
	void** ppFunctionPointer = nullptr;
	std::size_t FunctionSize = 0;
	std::size_t FunctionOriginalInstructionSize = 0;

	BYTE relative_jump[5]
	{
		0xE9, 0x00, 0x00, 0x00, 0x00
	};

	BYTE absolute_jump[14]
	{
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,				
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	};

	//Original untouched instructions of the original target
	BYTE oInstructions[50] {};

	//Original instructions of target, it may contain modified instructions to fix displacement
	BYTE gatewayInstructions[50] {};

	enum HookType
	{
		RealtiveJump,
		AbsoluteJump,
		Invalid
	};

	HookType curr_type = Invalid;
	bool is_hooked = false;

	DWORD alignment_fix = 0;
};

MadHook::Status CreateTrampolineHook(void* const pTargetFunction, void* pDetourFunction, void** ppFunctionPointer)
{
	if (!ppFunctionPointer || !pDetourFunction || !pTargetFunction)
		return MadHook::Status::MH_INVALID_ARGUMENT;

	WinTypes::SYSTEM_BASIC_INFORMATION sbi{};
	MadSyscall::Indirect::Invoke<void>("NtQuerySystemInformation", WinTypes::SystemBasicInformation, &sbi, sizeof(sbi), nullptr);

	if (sbi.AllocationGranularity == 0)
		sbi.AllocationGranularity = 1 << 16;

	DWORD dwMinimumSize		  = sizeof(TrampolineHookData::relative_jump);
	std::size_t function_size = Utility::GetFunctionSize(static_cast<BYTE*>(pTargetFunction));

	if (function_size < dwMinimumSize)
		return MadHook::Status::MH_FAILURE;

	TrampolineHookData hook_data {};
	hook_data.pTargetFunction = pTargetFunction;
	hook_data.ppFunctionPointer = ppFunctionPointer;
	hook_data.pDetourFunction = pDetourFunction;
	hook_data.FunctionSize = function_size;

	void* pAllocatedGateway = nullptr;

#ifdef _M_X64
	if(function_size >= sizeof(TrampolineHookData::relative_jump))
	{
		//relative jmp in x64 when possible
		if(void* pCloseMemory = Utility::FindCloseMemory(static_cast<BYTE*>(pTargetFunction), sbi.AllocationGranularity); pCloseMemory != nullptr)
		{
			//Gateway in range of -+ 2gigs
			pAllocatedGateway = pCloseMemory;
		
			std::size_t region_size = 1;
			NTSTATUS status = MadSyscall::Indirect::Invoke<NTSTATUS>("NtAllocateVirtualMemory", (HANDLE)-1, 
				&pAllocatedGateway, NULL,
				&region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
		
			if (status < 0)
				return MadHook::Status::MH_FAILURE;
		
			hook_data.curr_type = TrampolineHookData::RealtiveJump;
		}
		else if (function_size >= sizeof(TrampolineHookData::absolute_jump))
		{
			//Gateway can be anywhere
			std::size_t region_size = 1;
			NTSTATUS status = MadSyscall::Indirect::Invoke<NTSTATUS>("NtAllocateVirtualMemory", (HANDLE)-1,
				&pAllocatedGateway, NULL,
				&region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

			if (status < 0)
				return MadHook::Status::MH_FAILURE;

			hook_data.curr_type = TrampolineHookData::AbsoluteJump;
		}
	}
		
#else
	//x86 only requirement is the function to be greater equal to 5 bytes
	if (function_size >= sizeof(TrampolineHookData::relative_jump))
	{
		std::size_t region_size = 1;
		NTSTATUS status = MadSyscall::Indirect::Invoke<NTSTATUS>("NtAllocateVirtualMemory", (HANDLE)-1,
			&pAllocatedGateway, NULL,
			&region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (status < 0)
			return MadHook::Status::MH_FAILURE;

		hook_data.curr_type = TrampolineHookData::RealtiveJump;
	}
#endif

	*ppFunctionPointer = static_cast<BYTE*>(pAllocatedGateway) + 14;

	hook_data.Gateway = pAllocatedGateway;
	MemoryManager::Insert(typeid(TrampolineHookData), &hook_data, sizeof(TrampolineHookData));

	return MadHook::Status::MH_OK;
}

static void HandleInstructionsX64(ZydisDecodedInstruction const& decoded_instruction, TrampolineHookData const& hook_data,
								  const std::size_t total_instruction_size, BYTE* const pStart, 
								  BYTE*& gatewayInstructions, ZydisDecodedOperand const (&decoded_operand)[10])
{
	switch (decoded_instruction.mnemonic)
	{
		case ZYDIS_MNEMONIC_JMP:
		{
			BYTE abs_jmp[14]
			{
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};

			if (decoded_operand[0].mem.disp.has_displacement)
			{
				DWORD64* resolved_displacement = reinterpret_cast<DWORD64*>(pStart + decoded_operand[0].mem.disp.value);
				*reinterpret_cast<DWORD64**>(abs_jmp + 6) = *reinterpret_cast<DWORD64**>(resolved_displacement);
			}
			else
			{
				int jump_value = *reinterpret_cast<int*>((pStart - decoded_instruction.length) + 1);
				DWORD64* resolved_displacement = reinterpret_cast<DWORD64*>(pStart + jump_value);
				*reinterpret_cast<DWORD64**>(abs_jmp + 6) = resolved_displacement;
			}

			memcpy_s(gatewayInstructions + total_instruction_size - decoded_instruction.length, sizeof(hook_data.gatewayInstructions), abs_jmp, sizeof(abs_jmp));
			gatewayInstructions += sizeof(abs_jmp) - decoded_instruction.length;

			break;
		}

		default:
			break;
	}
}

static void HandleInstructionsX86(ZydisDecodedInstruction const& decoded_instruction, TrampolineHookData const& hook_data, const std::size_t total_instruction_size, BYTE* const pStart, BYTE*& gatewayInstructions)
{
	switch (decoded_instruction.mnemonic)
	{
		case ZYDIS_MNEMONIC_JMP:
		{
			BYTE jmp_instruction[5]{ 0xE9, 0x00, 0x00, 0x00, 0x00 };

			int jump_value = *reinterpret_cast<int*>( (pStart - decoded_instruction.length) + 1 );
			BYTE* resolved_displacement = pStart + jump_value;

			int* jump_offset = reinterpret_cast<int*>(resolved_displacement - (static_cast<BYTE*>(hook_data.Gateway) + 14 + sizeof(jmp_instruction) ));
			*reinterpret_cast<int**>(&jmp_instruction[1]) = jump_offset;

			memcpy_s(gatewayInstructions + total_instruction_size - decoded_instruction.length, sizeof(hook_data.gatewayInstructions), jmp_instruction, sizeof(jmp_instruction));

			break;
		}

		default:
			break;
	}
}

static MadHook::Status PrepareOriginalInstructions(TrampolineHookData& hook_data)
{
	for (size_t i = 0; i < sizeof(hook_data.oInstructions); i++)
	{
		hook_data.oInstructions[i] = '\x90';
		hook_data.gatewayInstructions[i] = '\x90';
	}

	DWORD dwMinimumSize = 0;

	switch (hook_data.curr_type)
	{
		case TrampolineHookData::RealtiveJump: dwMinimumSize = sizeof(hook_data.relative_jump); break;
		case TrampolineHookData::AbsoluteJump: dwMinimumSize = sizeof(hook_data.absolute_jump); break;
		case TrampolineHookData::Invalid: return MadHook::Status::MH_INVALID_HOOK_TYPE;
	}

	ZydisDecoder decoder{};
	ZydisDecodedInstruction decoded_instruction{};
	ZydisDecodedOperand decoded_operand[ZYDIS_MAX_OPERAND_COUNT] {};

#ifdef _M_X64 
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#endif

	std::size_t total_instruction_size = 0;

	BYTE* pStart = static_cast<BYTE*>(hook_data.pTargetFunction);
	BYTE* pEnd	 = pStart + hook_data.FunctionSize - 1;

	BYTE* gatewayInstructions = hook_data.gatewayInstructions;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, pStart, ZYDIS_MAX_INSTRUCTION_LENGTH, &decoded_instruction, decoded_operand)))
	{
		total_instruction_size += decoded_instruction.length;
		pStart				   += decoded_instruction.length;
		
		memcpy_s(gatewayInstructions + total_instruction_size - decoded_instruction.length, sizeof(hook_data.gatewayInstructions), static_cast<BYTE*>(hook_data.pTargetFunction) + total_instruction_size - decoded_instruction.length, decoded_instruction.length);

#ifndef _M_X64
		for (size_t i = 0; i < decoded_instruction.operand_count; i++)
		{
			if (decoded_operand[i].type == ZYDIS_OPERAND_TYPE_MEMORY && decoded_operand[i].mem.disp.has_displacement && decoded_operand[i].mem.base == ZYDIS_REGISTER_RIP)
			{
				BYTE* resolved_displacement = pStart + decoded_operand[i].mem.disp.value;

				BYTE* nip = static_cast<BYTE*>(hook_data.Gateway) + total_instruction_size;

				int32_t new_displacement = static_cast<int32_t>(resolved_displacement - nip);

				ZydisEncoderRequest encoder_request{};

				ZyanU8 buffer[ZYDIS_MAX_INSTRUCTION_LENGTH]{};

				ZyanUSize instruction_size = sizeof(buffer);
				decoded_operand[i].mem.disp.value = new_displacement;

				if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(&decoded_instruction, &decoded_operand[0], decoded_instruction.operand_count_visible, &encoder_request)))
					return MadHook::Status::TH_ENCODING_FAILURE;

				if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&encoder_request, &buffer, &instruction_size)))
					return MadHook::Status::TH_ENCODING_FAILURE;

				memcpy_s(gatewayInstructions + total_instruction_size - decoded_instruction.length, sizeof(hook_data.gatewayInstructions), buffer, sizeof(buffer));

				break;
			}
		}

		HandleInstructionsX86(decoded_instruction, hook_data, total_instruction_size, pStart, gatewayInstructions);
#else
		//I might add more stuff overtime for x64 since I already pretty much covered enough for x86
		HandleInstructionsX64(decoded_instruction, hook_data, total_instruction_size, pStart, gatewayInstructions, decoded_operand);
#endif

		if (total_instruction_size >= dwMinimumSize)
			break;
		
		if (pStart >= pEnd)
			break;
	}

	hook_data.FunctionOriginalInstructionSize = total_instruction_size;

	memcpy_s(hook_data.oInstructions, sizeof(hook_data.oInstructions), hook_data.pTargetFunction, total_instruction_size);

	return MadHook::Status::TH_OK;
}

static void PrepareHook(TrampolineHookData& hook_data)
{
	BYTE* pGateway = static_cast<BYTE*>(hook_data.Gateway) + 14;

	switch (hook_data.curr_type)
	{
		case TrampolineHookData::RealtiveJump:
			{
				//Used for the jump from the gateway to the target Function
				BYTE gateway_relative_jump[5]
				{
					0xE9, 0x00, 0x00, 0x00, 0x00
				};

				*reinterpret_cast<int32_t*>(&hook_data.relative_jump[1]) = static_cast<int32_t>( (pGateway - 14) - static_cast<BYTE*>(hook_data.pTargetFunction) - 5);

				memcpy_s(pGateway, 1 << 12, hook_data.gatewayInstructions, sizeof(hook_data.gatewayInstructions));

				pGateway += sizeof(hook_data.gatewayInstructions);

				*reinterpret_cast<int32_t*>(&gateway_relative_jump[1]) = static_cast<int32_t>( (static_cast<BYTE*>(hook_data.pTargetFunction) + (hook_data.FunctionOriginalInstructionSize)) - pGateway - 5);

				memcpy_s(pGateway, 1 << 12, gateway_relative_jump, sizeof(gateway_relative_jump));

				break;
			}

		case TrampolineHookData::AbsoluteJump:
			{
				//Used for the jump from the gateway to the target Function
				BYTE gateway_absolute_jump[14]
				{
					0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				};

				*reinterpret_cast<DWORD64*>(&hook_data.absolute_jump[6]) = reinterpret_cast<DWORD64>(pGateway) - 14;

				memcpy_s(pGateway, 1 << 12, hook_data.gatewayInstructions, sizeof(hook_data.gatewayInstructions));

				pGateway += sizeof(hook_data.gatewayInstructions);

				*reinterpret_cast<DWORD64*>(&gateway_absolute_jump[6]) = reinterpret_cast<DWORD64>(hook_data.pTargetFunction) + hook_data.FunctionOriginalInstructionSize;

				memcpy_s(pGateway, 1 << 12, gateway_absolute_jump, sizeof(gateway_absolute_jump));


				break;
			}
	}
}

static void PrepareGateway(TrampolineHookData& hook_data)
{
	BYTE* pGateway = static_cast<BYTE*>(hook_data.Gateway);

#ifdef _M_X64
	BYTE gateway_forwarder_jump[14]
	{
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	*reinterpret_cast<DWORD64*>(&gateway_forwarder_jump[6]) = reinterpret_cast<DWORD64>(hook_data.pDetourFunction);
#else
	BYTE gateway_forwarder_jump[14]
	{
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
	};

	*reinterpret_cast<DWORD**>(&gateway_forwarder_jump[2]) = reinterpret_cast<DWORD*>(&hook_data.pDetourFunction);
#endif
	memcpy_s(pGateway, 1 << 12, gateway_forwarder_jump, sizeof(gateway_forwarder_jump));
}

static void PlaceHook(TrampolineHookData& hook_data)
{
	ULONG old_page_access = 0;

	PVOID pTarget = hook_data.pTargetFunction;

	//TODO find a way to stay RW only, currently there is a chance to corrupt memory page if hooking one function which is close to the one im using at the same time. Example is NtSetInformationFile would cause my syscall to be in a RE section lol
	//Utility::ChangePageProtection(pTarget, PAGE_READWRITE, &old_page_access);
	Utility::ChangePageProtection(pTarget, PAGE_EXECUTE_READWRITE, &old_page_access);

	switch (hook_data.curr_type)
	{
		case TrampolineHookData::RealtiveJump:
			memcpy_s(hook_data.pTargetFunction, sizeof(hook_data.relative_jump), hook_data.relative_jump, sizeof(hook_data.relative_jump));
			break;

		case TrampolineHookData::AbsoluteJump:
			memcpy_s(hook_data.pTargetFunction, sizeof(hook_data.absolute_jump), hook_data.absolute_jump, sizeof(hook_data.absolute_jump));
			break;
	}

	Utility::ChangePageProtection(pTarget, old_page_access, &old_page_access);

	hook_data.is_hooked = true;
}

static void RemoveHook(TrampolineHookData& hook_data)
{
	ULONG old_page_access = 0;

	PVOID pTarget = hook_data.pTargetFunction;

	//Utility::ChangePageProtection(pTarget, PAGE_READWRITE, &old_page_access);
	Utility::ChangePageProtection(pTarget, PAGE_EXECUTE_READWRITE, &old_page_access);

	switch (hook_data.curr_type)
	{
		case TrampolineHookData::RealtiveJump:
			memcpy_s(hook_data.pTargetFunction, hook_data.FunctionOriginalInstructionSize, hook_data.oInstructions, hook_data.FunctionOriginalInstructionSize);
			break;

		case TrampolineHookData::AbsoluteJump:
			memcpy_s(hook_data.pTargetFunction, hook_data.FunctionOriginalInstructionSize, hook_data.oInstructions, sizeof(hook_data.oInstructions));
			break;
	}

	Utility::ChangePageProtection(pTarget, old_page_access, &old_page_access);

	hook_data.is_hooked = false;
}

MadHook::Status EnableTrampolineHook(void* const pTargetFunction)
{
	ThreadManager::ThreadSuspend suspend;

	for (MemoryManager::PLIST_ENTRY curr = nullptr; LoopOverEntry(typeid(TrampolineHookData), curr); curr = curr->Flink)
	{
		if(static_cast<TrampolineHookData*>(curr->pData)->pTargetFunction == pTargetFunction)
		{
			TrampolineHookData* p_trampoline_hook_data = static_cast<TrampolineHookData*>(curr->pData);

			ULONG old_page_access = 0;

			if(Utility::ChangePageProtection(p_trampoline_hook_data->Gateway, PAGE_READWRITE, &old_page_access) < 0)
				break;

			if(PrepareOriginalInstructions(*p_trampoline_hook_data) == MadHook::Status::TH_OK)
			{
				PrepareGateway(*p_trampoline_hook_data);
				PrepareHook(*p_trampoline_hook_data);
				PlaceHook(*p_trampoline_hook_data);
			}

			if (Utility::ChangePageProtection(p_trampoline_hook_data->Gateway, old_page_access, &old_page_access) < 0)
				break;

			return MadHook::Status::MH_OK;
		}
	}

	return MadHook::Status::MH_FAILURE;
}

MadHook::Status EnableAllTrampolineHooks()
{
	ThreadManager::ThreadSuspend suspend;

	for (MemoryManager::PLIST_ENTRY curr = nullptr; LoopOverEntry(typeid(TrampolineHookData), curr); curr = curr->Flink)
	{
		TrampolineHookData* p_trampoline_hook_data = static_cast<TrampolineHookData*>(curr->pData);

		ULONG old_page_access = 0;

		if (Utility::ChangePageProtection(p_trampoline_hook_data->Gateway, PAGE_READWRITE, &old_page_access) < 0)
			return MadHook::Status::MH_FAILURE;

		if (PrepareOriginalInstructions(*p_trampoline_hook_data) == MadHook::Status::TH_OK)
		{
			PrepareGateway(*p_trampoline_hook_data);
			PrepareHook(*p_trampoline_hook_data);
			PlaceHook(*p_trampoline_hook_data);
		}

		if (Utility::ChangePageProtection(p_trampoline_hook_data->Gateway, old_page_access, &old_page_access) < 0)
			return MadHook::Status::MH_FAILURE;
	}

	return MadHook::Status::MH_OK;
}

MadHook::Status DisableTrampolineHook(void* pTargetFunction)
{
	ThreadManager::ThreadSuspend suspend;

	//for (MemoryManager::PLIST_ENTRY curr = nullptr; LoopOverEntry(typeid(TrampolineHookData), curr);)
	//{
	//	if (static_cast<TrampolineHookData*>(curr->pData)->pTargetFunction == pTargetFunction)
	//	{
	//		TrampolineHookData* p_trampoline_hook_data = static_cast<TrampolineHookData*>(curr->pData);
	//
	//		if (p_trampoline_hook_data->is_hooked)
	//			RemoveHook(*p_trampoline_hook_data);
	//
	//		MemoryManager::RemoveEntry(curr);
	//
	//		return MadHook::Status::MH_OK;
	//	}
	//}

	MemoryManager::PLIST_ENTRY tail = MemoryManager::GetTail();
	for (MemoryManager::PLIST_ENTRY curr = MemoryManager::GetHead(); curr != tail;)
	{
		if (curr->type != typeid(TrampolineHookData))
		{
			curr = curr->Flink;
			continue;
		}

		if (static_cast<TrampolineHookData*>(curr->pData)->pTargetFunction == pTargetFunction)
		{
			TrampolineHookData* p_trampoline_hook_data = static_cast<TrampolineHookData*>(curr->pData);
		
			if (p_trampoline_hook_data->is_hooked)
				RemoveHook(*p_trampoline_hook_data);
		
			MemoryManager::RemoveEntry(curr);
		
			return MadHook::Status::MH_OK;
		}
	}

	return MadHook::Status::TH_FAILURE;
}

MadHook::Status DisableAllTrampolineHooks()
{
	ThreadManager::ThreadSuspend suspend;

	//for (MemoryManager::PLIST_ENTRY curr = nullptr; LoopOverEntry(typeid(TrampolineHookData), curr);)
	//{
	//	TrampolineHookData* p_trampoline_hook_data = static_cast<TrampolineHookData*>(curr->pData);
	//
	//	if(p_trampoline_hook_data->is_hooked)
	//		RemoveHook(*p_trampoline_hook_data);
	//
	//	MemoryManager::RemoveEntry(curr);
	//}

	MemoryManager::PLIST_ENTRY tail = MemoryManager::GetTail();
	for (MemoryManager::PLIST_ENTRY curr = MemoryManager::GetHead(); curr != tail;)
	{
		if(curr->type != typeid(TrampolineHookData))
		{
			curr = curr->Flink;
			continue;
		}

		TrampolineHookData* p_trampoline_hook_data = static_cast<TrampolineHookData*>(curr->pData);

		if (p_trampoline_hook_data->is_hooked)
			RemoveHook(*p_trampoline_hook_data);

		MemoryManager::RemoveEntry(curr);
	}

	return MadHook::Status::MH_OK;
}
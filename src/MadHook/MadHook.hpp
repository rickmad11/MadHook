#pragma once

namespace MadHook
{
	enum HookType
	{
		Trampoline
	};

	enum class Status : BYTE
	{
		//MadHook Errors
		MH_OK,
		MH_FAILURE,
		MH_SYSCALL_INIT_FAILURE,
		MH_INVALID_HOOK_TYPE,
		MH_INVALID_ARGUMENT,

		//MadSyscall Errors
		MS_OK,
		MS_FAILURE,
		MS_FAILURE_ON_FUNCTION_RESOLVING,
		MS_FAILURE_ON_ADDRESS_RESOLVING,

		//MemoryManager
		MM_FAILURE_ON_INIT,
		MM_FAILURE_ON_UN_INIT,
		MM_OK,

		//TrampolineHook
		TH_ENCODING_FAILURE,
		TH_FAILURE,
		TH_OK,
	};
}

namespace MadHook
{
	Status Initialize();
	Status UnInitialize();

	Status CreateHook(void* pTargetFunction, void* pDetourFunction, void** ppFunctionPointer, HookType hooktype = Trampoline);
	Status EnableHook(void* const pTargetFunction, HookType hooktype = Trampoline);
	Status EnableAllHooks(HookType hooktype = Trampoline);
	Status DisableAllHooks(HookType hooktype = Trampoline);
	Status DisableHook(void* const pTargetFunction, HookType hooktype = Trampoline);
}
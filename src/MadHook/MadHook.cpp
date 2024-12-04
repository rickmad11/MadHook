#include "pch.h"

#include "MadHook.hpp"
#include "MadSyscalls/Syscalls.hpp"
#include "MemoryManager/MemoryManager.hpp"
#include "ThreadManager/ThreadManager.hpp"
#include "Trampoline/TrampolineHook.hpp"

namespace MadHook
{
	Status Initialize()
	{
		ThreadManager::LockGuard lock;

		if (Status ms_status = MemoryManager::Init(); ms_status != Status::MM_OK)
			return ms_status;

		if(Status ms_status = MadSyscall::Initialize(); ms_status != Status::MS_OK)
			return ms_status;

		return Status::MH_OK;
	}

	//Make sure to disable all hooks with MadHook::DisableAllHooks() or MadHook::DisableHook() before calling this function
	Status UnInitialize()
	{
		ThreadManager::LockGuard lock;

		if (Status ms_status = MemoryManager::UnInit(); ms_status != Status::MM_OK)
			return ms_status;

		return Status::MH_OK;
	}

	Status CreateHook(void* pTargetFunction, void* pDetourFunction, void** ppFunctionPointer, HookType hooktype)
	{
		ThreadManager::LockGuard lock;

		switch (hooktype)
		{
			case Trampoline:
				return CreateTrampolineHook(pTargetFunction, pDetourFunction, ppFunctionPointer);

			default:
				return Status::MH_INVALID_HOOK_TYPE;
		}
	}

	Status EnableHook(void* const pTargetFunction, HookType hooktype)
	{
		ThreadManager::LockGuard lock;

		switch (hooktype)
		{
			case Trampoline:
				return EnableTrampolineHook(pTargetFunction);

			default:
				return Status::MH_INVALID_HOOK_TYPE;
		}
	}

	Status EnableAllHooks(HookType hooktype)
	{
		ThreadManager::LockGuard lock;

		switch (hooktype)
		{
			case Trampoline:
				return EnableAllTrampolineHooks();

			default:
				return Status::MH_INVALID_HOOK_TYPE;
		}
	}

	Status DisableAllHooks(HookType hooktype)
	{
		ThreadManager::LockGuard lock;

		switch (hooktype)
		{
		case Trampoline:
			return DisableAllTrampolineHooks();

		default:
			return Status::MH_INVALID_HOOK_TYPE;
		}
	}

	Status DisableHook(void* const pTargetFunction, HookType hooktype)
	{
		ThreadManager::LockGuard lock;

		switch (hooktype)
		{
		case Trampoline:
			return DisableTrampolineHook(pTargetFunction);

		default:
			return Status::MH_INVALID_HOOK_TYPE;
		}
	}
}

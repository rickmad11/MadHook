#include "pch.h"
#include "ThreadManager.hpp"

#include "MadSyscalls/Syscalls.hpp"

namespace ThreadManager
{
	LockGuard::LockGuard()
	{
		while (_InterlockedCompareExchange8(reinterpret_cast<char volatile*>(&s_bSpinlock), true, false))
			std::this_thread::sleep_for(std::chrono::microseconds(1000));
	}

	LockGuard::~LockGuard()
	{
		_InterlockedExchange8(reinterpret_cast<char volatile*>(&s_bSpinlock), false);
	}

	ThreadSuspend::ThreadSuspend()
	{
		while (_InterlockedCompareExchange8(reinterpret_cast<char volatile*>(&s_bSpinlock), true, false))
			std::this_thread::sleep_for(std::chrono::microseconds(1000));

		dwThreadId = GetCurrentThreadId();
		thread_handle.reserve(50);

		ULONG sbiSize = 0;
		(void)MadSyscall::Indirect::Invoke<NTSTATUS>("NtQuerySystemInformation", WinTypes::SystemProcessInformation, nullptr, 0, &sbiSize);

		std::unique_ptr<BYTE[]> spiBuffer = std::make_unique_for_overwrite<BYTE[]>(sbiSize);
		(void)MadSyscall::Indirect::Invoke<NTSTATUS>("NtQuerySystemInformation", WinTypes::SystemProcessInformation, spiBuffer.get(), sbiSize, nullptr);

		WinTypes::PSYSTEM_PROCESS_INFORMATION pspi = reinterpret_cast<WinTypes::PSYSTEM_PROCESS_INFORMATION>(spiBuffer.get());

		while (reinterpret_cast<std::uintptr_t>(pspi->UniqueProcessId) != GetCurrentProcessId() && pspi->NextEntryOffset)
			pspi = reinterpret_cast<WinTypes::PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pspi) + pspi->NextEntryOffset);

		for (std::size_t index = 0; index < pspi->NumberOfThreads; index++)
		{
			if(pspi->Threads[index].ClientId.UniqueThread == dwThreadId)
				continue;

			WinTypes::OBJECT_ATTRIBUTES object{ .Length = sizeof(WinTypes::OBJECT_ATTRIBUTES) };

			HANDLE hThread = nullptr;
			(void)MadSyscall::Indirect::Invoke<NTSTATUS>("NtOpenThread", &hThread, THREAD_SUSPEND_RESUME, &object, &pspi->Threads[index].ClientId);

			(void)MadSyscall::Indirect::Invoke<NTSTATUS>("NtSuspendThread", hThread, nullptr);

			thread_handle.emplace_back(hThread);
		}

		_InterlockedExchange8(reinterpret_cast<char volatile*>(&s_bSpinlock), false);
	}

	ThreadSuspend::~ThreadSuspend()
	{
		while (_InterlockedCompareExchange8(reinterpret_cast<char volatile*>(&s_bSpinlock), true, false))
			std::this_thread::sleep_for(std::chrono::microseconds(1000));

		for(HANDLE hThread : thread_handle)
		{
			(void)MadSyscall::Indirect::Invoke<NTSTATUS>("NtResumeThread", hThread, nullptr);
			(void)MadSyscall::Indirect::Invoke<NTSTATUS>("NtClose", hThread);
		}

		_InterlockedExchange8(reinterpret_cast<char volatile*>(&s_bSpinlock), false);
	}
}

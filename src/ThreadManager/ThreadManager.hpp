#pragma once

namespace ThreadManager
{
	class LockGuard
	{
	public:
		LockGuard();
		~LockGuard();

		LockGuard(LockGuard const&) = delete;
		LockGuard& operator=(LockGuard const&) = delete;

		LockGuard(LockGuard&&) = delete;
		LockGuard& operator=(LockGuard&&) = delete;

	private:
		inline static bool s_bSpinlock = false;
	};

	class ThreadSuspend
	{
	public:
		ThreadSuspend();
		~ThreadSuspend();

		ThreadSuspend(LockGuard const&) = delete;
		ThreadSuspend& operator=(ThreadSuspend const&) = delete;

		ThreadSuspend(LockGuard&&) = delete;
		ThreadSuspend& operator=(ThreadSuspend&&) = delete;

	private:
		inline static bool s_bSpinlock = false;
		DWORD dwThreadId = 0;
		std::vector<HANDLE> thread_handle;
	};
}
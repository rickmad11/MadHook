#pragma once

namespace Utility
{
	std::size_t GetFunctionSize(BYTE const* pTargetFunction);
	void* FindCloseMemory(BYTE const* const pTargetFunction, std::size_t dwAllocationGranularity);
	NTSTATUS ChangePageProtection(PVOID BaseAddress, ULONG NewAccessProtection, PULONG OldAccessProtection);
}
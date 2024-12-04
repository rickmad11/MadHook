#pragma once
#include "MadHook/MadHook.hpp"

MadHook::Status CreateTrampolineHook(void* pTargetFunction, void* pDetourFunction, void** ppFunctionPointer);
MadHook::Status EnableTrampolineHook(void* const pTargetFunction);
MadHook::Status EnableAllTrampolineHooks();
MadHook::Status DisableAllTrampolineHooks();
MadHook::Status DisableTrampolineHook(void* pTargetFunction);
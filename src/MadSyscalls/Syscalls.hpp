#pragma once

#include "MadHook/MadHook.hpp"
#include "WinTypes.hpp"

namespace MadSyscall
{
	using namespace WinTypes;

	MadHook::Status Initialize();

	void* GetFunctionAddress(std::string_view function_name);
	void* GetModuleAddress(std::wstring_view module_name);

	BYTE* PrepareShellcode(BYTE* const address_of_function, bool direct);
}

namespace MadSyscall::Direct
{
	using namespace WinTypes;

	template<typename RETURN, typename... Args>
	RETURN WINAPI Invoke(std::string_view function_name, Args... args)
	{
		BYTE* const address_of_function = static_cast<BYTE*>(GetFunctionAddress(function_name));

		if (!address_of_function)
			return RETURN{};

		if (BYTE* const shellcode = PrepareShellcode(address_of_function, true))
		{
			RETURN(WINAPI * pNativeFunction)(Args...) = reinterpret_cast<RETURN(WINAPI*)(Args...)>(shellcode);
			return pNativeFunction(args...);
		}

		return RETURN{};
	}
}

namespace MadSyscall::Indirect
{
	using namespace WinTypes;

	template<typename RETURN, typename... Args>
	RETURN WINAPI Invoke(std::string_view function_name, Args... args)
	{
		BYTE* const address_of_function = static_cast<BYTE*>(GetFunctionAddress(function_name));

		if (!address_of_function)
			return RETURN{};

		if(BYTE* const shellcode = PrepareShellcode(address_of_function, false))
		{
			RETURN(WINAPI * pNativeFunction)(Args...) = reinterpret_cast<RETURN(WINAPI*)(Args...)>(shellcode);
			return pNativeFunction(args...);
		}

		return RETURN{};
	}
}
#pragma once

#include "WinTypes.hpp"

typedef LONG (WINAPI* RtlCompareUnicodeString)(
	WinTypes::PUNICODE_STRING String1,
	WinTypes::PUNICODE_STRING String2,
	BOOLEAN          CaseInSensitive
);

typedef VOID (WINAPI*RtlInitUnicodeString)(
	WinTypes::PUNICODE_STRING DestinationString,
	PCWSTR SourceString
);
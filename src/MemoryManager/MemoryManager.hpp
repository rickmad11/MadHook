#pragma once

#include "MadHook/MadHook.hpp"

namespace MemoryManager
{
	//The design of my circular doubly linked list is quite different from the ones you will find online.
	//The way I iterate and manipulate the list is therefore very different.
	//It is also not similar to the one Windows is using at all.
	//I might change the list behaviour at some point in the future.

	//The head data will be the same when reversing the list.
	typedef struct LIST_ENTRY
	{
		LIST_ENTRY* Flink = nullptr;
		LIST_ENTRY* Blink = nullptr;
		PVOID pData		  = nullptr;
		std::type_index type;
	}*PLIST_ENTRY;

	MadHook::Status Init();
	MadHook::Status UnInit();

	bool Insert(std::type_index type, PVOID pData, std::size_t qwBytes);
	bool InsertAt(std::size_t pos, std::type_index type, PVOID pData, std::size_t qwBytes);
	bool Append(std::type_index type, PVOID pData, std::size_t qwBytes);
	void ReverseList();

	bool LoopOverEntry(std::type_index type, PLIST_ENTRY& o_curr);
	bool RemoveEntry(std::type_index type, std::size_t offset, PVOID cmpValue, std::size_t cmpValueSize);
	bool RemoveEntry(PLIST_ENTRY& entry_to_remove);
	PLIST_ENTRY GetEntry(std::type_index type, std::size_t offset, PVOID cmpValue, std::size_t cmpValueSize);

	PLIST_ENTRY GetHead();
	PLIST_ENTRY GetTail();
}

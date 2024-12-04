#include "pch.h"

#include "MemoryManager.hpp"

namespace MemoryManager
{
	namespace Global
	{
		static HANDLE hHeap     = nullptr;
		static PLIST_ENTRY head = nullptr;
		static PLIST_ENTRY tail = nullptr;
	}

	MadHook::Status Init()
	{
		Global::hHeap = HeapCreate(NULL, NULL, NULL);

		if (!Global::hHeap)
			return MadHook::Status::MM_FAILURE_ON_INIT;

		Global::head = static_cast<PLIST_ENTRY>(HeapAlloc(Global::hHeap, HEAP_ZERO_MEMORY, sizeof(LIST_ENTRY)));

		if (!Global::head)
			return MadHook::Status::MM_FAILURE_ON_INIT;

		Global::head->Flink = Global::head;
		Global::head->Blink = Global::head;
		Global::head->type  = typeid(LIST_ENTRY);

		Global::tail = Global::head;

		return MadHook::Status::MM_OK;
	}

	MadHook::Status UnInit()
	{
		//everything that we have in our lists was allocated with this heap
		if (!HeapDestroy(Global::hHeap))
			return MadHook::Status::MM_FAILURE_ON_UN_INIT;

		return MadHook::Status::MM_OK;
	}

	bool Insert(std::type_index type, PVOID pData, std::size_t qwBytes)
	{
		if (Global::head == nullptr)
			return false;

		PLIST_ENTRY new_entry = static_cast<PLIST_ENTRY>(HeapAlloc(Global::hHeap, HEAP_ZERO_MEMORY, sizeof(LIST_ENTRY)));

		new_entry->type  = type;
		new_entry->Flink = Global::head;
		new_entry->Blink = Global::tail;

		new_entry->pData = HeapAlloc(Global::hHeap, HEAP_ZERO_MEMORY, qwBytes);
		memcpy_s(new_entry->pData, qwBytes, pData, qwBytes);

		Global::tail->Flink = new_entry;
		Global::head->Blink = new_entry;

		Global::head = new_entry;

		return true;
	}

	bool InsertAt(std::size_t pos, std::type_index type, PVOID pData, std::size_t qwBytes)
	{
		bool is_inserted = false;

		std::size_t curr_pos = 0;
		for (PLIST_ENTRY curr = Global::head; curr != Global::tail; curr = curr->Flink, ++curr_pos)
		{
			if(curr_pos == pos)
			{
				PLIST_ENTRY new_entry = static_cast<PLIST_ENTRY>(HeapAlloc(Global::hHeap, HEAP_ZERO_MEMORY, sizeof(LIST_ENTRY)));

				new_entry->type  = type;
				new_entry->Flink = curr;
				new_entry->Blink = curr->Blink;

				new_entry->pData = HeapAlloc(Global::hHeap, HEAP_ZERO_MEMORY, qwBytes);
				memcpy_s(new_entry->pData, qwBytes, pData, qwBytes);

				curr->Blink->Flink = new_entry;
				curr->Blink = new_entry;

				is_inserted = true;
				break;
			}
		}

		return is_inserted;
	}

	bool Append(std::type_index type, PVOID pData, std::size_t qwBytes)
	{
		PLIST_ENTRY new_entry = static_cast<PLIST_ENTRY>(HeapAlloc(Global::hHeap, HEAP_ZERO_MEMORY, sizeof(LIST_ENTRY)));

		new_entry->type = type;
		new_entry->Flink = Global::tail;
		new_entry->Blink = Global::tail->Blink;

		new_entry->pData = HeapAlloc(Global::hHeap, HEAP_ZERO_MEMORY, qwBytes);
		memcpy_s(new_entry->pData, qwBytes, pData, qwBytes);

		Global::tail->Blink->Flink = new_entry;
		Global::tail->Blink = new_entry;

		return true;
	}

	void ReverseList()
	{
		for (PLIST_ENTRY curr = Global::tail; curr != Global::head; curr = curr->Flink)
		{
			PLIST_ENTRY FlinkTemp = curr->Flink;

			curr->Flink = curr->Blink;
			curr->Blink = FlinkTemp;
		}

		PLIST_ENTRY const oTail = Global::tail;

		Global::head->Blink = Global::head->Flink;
		Global::head->Flink = oTail;

		Global::tail = Global::head;

		Global::head = oTail;

		Global::head->pData = Global::tail->pData;
		Global::head->type  = Global::tail->type;

		Global::tail->pData = nullptr;
		Global::tail->type  = typeid(void);
	}

	PLIST_ENTRY VerifyMatchingEntryData(PLIST_ENTRY curr, std::size_t offset, PVOID cmpValue, std::size_t cmpValueSize)
	{
		char const* pData = static_cast<char const*>(curr->pData);

		if (cmpValueSize == sizeof(char))
		{
			if (*(pData + offset) == *static_cast<char const*>(cmpValue))
				return curr;
		}

		if (cmpValueSize == sizeof(short))
		{
			if (*reinterpret_cast<short const*>(pData + offset) == *static_cast<short const*>(cmpValue))
				return curr;
		}

		if (cmpValueSize == sizeof(int))
		{
			if (*reinterpret_cast<int const*>(pData + offset) == *static_cast<int const*>(cmpValue))
				return curr;
		}

		if (cmpValueSize == sizeof(void*))
		{
			if (*reinterpret_cast<long long int const*>(pData + offset) == *static_cast<long long int const*>(cmpValue))
				return curr;
		}

		return nullptr;
	}

	bool RemoveEntry(std::type_index type, std::size_t offset, PVOID cmpValue, std::size_t cmpValueSize)
	{
		for (PLIST_ENTRY curr = Global::head; curr != Global::tail; curr = curr->Flink)
		{
			if (curr->type == type)
			{
				if (cmpValue == nullptr)
					return curr;

				if (PLIST_ENTRY found_entry = VerifyMatchingEntryData(curr, offset, cmpValue, cmpValueSize); found_entry != nullptr)
				{
					if(found_entry == Global::head)
						Global::head = found_entry->Flink;

					if (found_entry->pData)
					{
						(void)HeapFree(Global::hHeap, NULL, found_entry->pData);
						found_entry->pData = nullptr;
					}

					found_entry->Blink->Flink = found_entry->Flink;
					found_entry->Flink->Blink = found_entry->Blink;

					(void)HeapFree(Global::hHeap, NULL, found_entry);
					
					return true;
				}
			}
		}

		return false;
	}

	bool RemoveEntry(PLIST_ENTRY& entry_to_remove)
	{
		for (PLIST_ENTRY curr = Global::head; curr != Global::tail; curr = curr->Flink)
		{
			if (curr == entry_to_remove)
			{
				if (entry_to_remove == Global::head)
					Global::head = entry_to_remove->Flink;

				if (entry_to_remove->pData)
				{
					(void)HeapFree(Global::hHeap, NULL, entry_to_remove->pData);
					entry_to_remove->pData = nullptr;
				}

				entry_to_remove->Blink->Flink = entry_to_remove->Flink;
				entry_to_remove->Flink->Blink = entry_to_remove->Blink;

				PLIST_ENTRY temp = entry_to_remove;
				entry_to_remove = temp->Flink;

				(void)HeapFree(Global::hHeap, NULL, temp);

				return true;
			}
		}

		return false;
	}

	PLIST_ENTRY GetEntry(std::type_index type, std::size_t offset, PVOID cmpValue, std::size_t cmpValueSize)
	{
		for (PLIST_ENTRY curr = Global::head; curr != Global::tail; curr = curr->Flink)
		{
			if(curr->type == type)
			{
				//Yes using a Template here would be the way of doing this however I would have to move some stuff for instance the globals because of how templates instantiate

				if (cmpValue == nullptr)
					return curr;

				if (PLIST_ENTRY found_entry = VerifyMatchingEntryData(curr, offset, cmpValue, cmpValueSize); found_entry != nullptr)
					return found_entry;
			}
		}

		return nullptr;
	}

	bool LoopOverEntry(std::type_index type, PLIST_ENTRY& o_curr)
	{
		if (o_curr == nullptr)
			o_curr = Global::head;

		for (PLIST_ENTRY curr = o_curr; curr != Global::tail; curr = curr->Flink)
		{
			if (curr->type == type)
			{
				o_curr = curr;
				return true;
			}
		}

		return false;
	}

	PLIST_ENTRY GetHead()
	{
		return Global::head;
	}

	PLIST_ENTRY GetTail()
	{
		return Global::tail;
	}
}

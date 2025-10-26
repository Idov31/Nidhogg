#pragma once
#include "pch.h"
#include "AutoLock.h"
#include "MemoryHelper.h"

template<typename List>
concept ListType = requires(List list) {
	list.Count;
	list.Lock;
	list.Items;
		requires sizeof(list.Count) == sizeof(SIZE_T);
		requires sizeof(list.Lock) == sizeof(FastMutex);
		requires sizeof(list.Items) == sizeof(PLIST_ENTRY);
};

template<typename ListItem>
concept ListItemType = requires(ListItem item) {
	item.Entry;
		requires sizeof(item.Entry) == sizeof(LIST_ENTRY);
};

template<ListItemType ListItem, typename Searchable>
using MatcherFunction = bool(*)(_In_ const ListItem* item, _In_ Searchable searchable);

template<ListItemType ListItem>
using CleanupFunction = void(*)(_In_ ListItem* item);

/*
* Description:
* InitializeList is responsible for initializing a list structure.
* 
* Parameters:
* @list [_Inout_ List] -- List to initialize.
* 
* Returns:
* @bool				   -- Whether successfully initialized or not.
*/
_IRQL_requires_max_(APC_LEVEL)
template<ListType List>
inline bool InitializeList(_Inout_ List* list) {
	if (!list)
		return false;
	list->Count = 0;
	list->Items = AllocateMemory<PLIST_ENTRY>(sizeof(LIST_ENTRY));

	if (!list->Items)
		return false;

	InitializeListHead(list->Items);
	list->Lock.Init();
	return true;
}

/*
* Description:
* AddEntry is responsible for adding an entry to a list.
*
* Parameters:
* @entry	  [_In_ EntryType]		 -- Entry to add.
*
* Returns:
* @bool								 -- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
template<ListType List, ListItemType ListItem>
inline void AddEntry(_Inout_ List* list, _In_ ListItem* entryToAdd) {
	if (!list || !entryToAdd)
		return;
	InitializeListHead(&entryToAdd->Entry);

	AutoLock locker(list->Lock);
	list->Count++;
	InsertTailList(list->Items, &entryToAdd->Entry);
}

/*
* Description:
* FindListEntry is responsible for finding a list entry based on a matcher function.
*
* Parameters:
* @list			[_In_ List]			   -- List to search in.
* @searchable	[_In_ Searchable]	   -- Searchable item to match against.
* @function		[_In_ MatcherFunction] -- Function to match the entry against the searchable item.
*
* Returns:
* @ListItem*						   -- Pointer to the found list item, or NULL if not found.
*/
_IRQL_requires_max_(APC_LEVEL)
template<ListType List, ListItemType ListItem, typename Searchable>
inline ListItem* FindListEntry(_In_ const List& list, _In_ Searchable searchable, 
	_In_ MatcherFunction<ListItem, Searchable> function) noexcept {
	if (!function)
		return NULL;
	AutoLock locker(const_cast<FastMutex&>(list.Lock));

	if (list.Count == 0)
		return NULL;
	PLIST_ENTRY currentEntry = list.Items;

	do {
		ListItem* item = CONTAINING_RECORD(currentEntry, ListItem, Entry);

		if (function(item, searchable))
			return item;
		currentEntry = currentEntry->Flink;
	} while (currentEntry != list.Items);
	return NULL;
}

/*
* Description:
* RemoveListEntry is responsible for remove an entry from a list.
*
* Parameters:
* @list		[_Inout_ List]		 -- List to remove from.
* @entry	[_In_ ListItem*]	 -- Entry to remove.
*
* Returns:
* @bool							 -- Whether successfully removed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
template<ListType List, ListItemType ListItem>
inline bool RemoveListEntry(_Inout_ List* list, _In_ ListItem* entry) {
	if (!list || !entry)
		return false;

	AutoLock locker(list->Lock);
	
	if (!RemoveEntryList(&entry->Entry))
		return false;
	list->Count--;
	FreeVirtualMemory(entry);
	return true;
}

/*
* Description:
* ClearList is responsible for clearing a list.
*
* Parameters:
* @list [_Inout_ List] -- List to clear.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
template<ListType List, ListItemType ListItem>
inline void ClearList(_Inout_ List* list) {
	ListItem* entry = nullptr;
	PLIST_ENTRY next = nullptr;

	if (!list)
		return;
	AutoLock locker(list->Lock);

	if (list->Count == 0 || !list->Items)
		return;
	PLIST_ENTRY current = list->Items;

	while (current->Flink != list->Items) {
		current = current->Flink;
		entry = CONTAINING_RECORD(current, ListItem, Entry);
		next = current->Flink;
		RemoveEntryList(current);
		FreeVirtualMemory(entry);
		current = next;
	}

	list->Count = 0;
	InitializeListHead(list->Items);
}

/*
* Description:
* ClearList is responsible for clearing a list.
*
* Parameters:
* @list [_Inout_ List] -- List to clear.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
template<ListType List, ListItemType ListItem>
inline void ClearList(_Inout_ List* list, _In_ CleanupFunction<ListItem> function) {
	ListItem* entry = nullptr;

	if (!list || !function)
		return;
	list->Lock.Lock();

	if (list->Count == 0 || !list->Items)
		return;
	PLIST_ENTRY current = list->Items;

	while (current->Flink != list->Items) {
		current = current->Flink;
		entry = CONTAINING_RECORD(current, ListItem, Entry);
		current = current->Flink;
		list->Lock.Unlock();
		function(entry);
		list->Lock.Lock();
	}

	list->Count = 0;
	InitializeListHead(list->Items);
	list->Lock.Unlock();
}
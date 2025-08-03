#pragma once
#include "pch.h"
#include "MemoryHelper.hpp"
#include "MemoryUtils.h"

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
using MatcherFunction = bool(*)(const ListItem* item, Searchable searchable);

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
inline void AddEntry(_Inout_ List list, _In_ ListItem* entryToAdd) {
	InitializeListHead(&entryToAdd->Entry);

	AutoLock locker(list.Lock);
	list.Count++;
	InsertTailList(list.Items, &entryToAdd->Entry);
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
_IRQL_requires_max_(DISPATCH_LEVEL)
template<ListType List, ListItemType ListItem, typename Searchable>
inline ListItem* FindListEntry(_In_ List list, _In_ Searchable searchable, _In_ MatcherFunction<ListItem, Searchable> function) {
	AutoLock locker(list.Lock);

	if (list.Count == 0)
		return NULL;
	PLIST_ENTRY currentEntry = list.Items;

	while (currentEntry->Flink != list.Items) {
		currentEntry = currentEntry->Flink;
		ListItem* item = CONTAINING_RECORD(currentEntry, ListItem, Entry);

		if (function(item, searchable))
			return item;
		currentEntry = currentEntry->Flink;
	}
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
inline bool RemoveListEntry(_Inout_ List list, _In_ ListItem* entry) {
	AutoLock locker(list.Lock);
	
	if (!RemoveEntryList(&entry->Entry))
		return false;
	list.Count--;
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
inline void ClearList(_Inout_ List list) {
	AutoLock locker(list.Lock);

	while (!IsListEmpty(list.Items)) {
		PLIST_ENTRY current = RemoveHeadList(list.Items);
		ListItem* entry = CONTAINING_RECORD(current, ListItem, Entry);
		FreeVirtualMemory(entry);
	}
	list.Count = 0;
}
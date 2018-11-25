#pragma once
#include "../../../include/common_header.h"

class capstone_winkernel final
{
private:
	static capstone_winkernel* m_Instance;
public:
	capstone_winkernel();
	~capstone_winkernel();

	void* __cdecl operator new(_In_ size_t count)
	{
		return (void*)ExAllocatePool(NonPagedPool, count);
	}

	void __cdecl operator delete(_In_ PVOID object)
	{
		ExFreePool(object);
	}

	capstone_winkernel* GetInstance();
	void Release();
};
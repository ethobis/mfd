#include "capstone_winkernel.h"

capstone_winkernel* capstone_winkernel::m_Instance = nullptr;

capstone_winkernel::capstone_winkernel()
{
}

capstone_winkernel::~capstone_winkernel()
{
}

capstone_winkernel* capstone_winkernel::GetInstance()
{
	if (nullptr == m_Instance)
	{
		m_Instance = new capstone_winkernel();
	}
	return m_Instance;
}

void capstone_winkernel::Release()
{
	if (nullptr != m_Instance)
	{
		delete m_Instance;
		m_Instance = nullptr;
	}
}

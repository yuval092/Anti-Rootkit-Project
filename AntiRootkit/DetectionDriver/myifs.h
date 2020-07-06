#pragma once

#include "Common.h"

#if (NTDDI_VERSION >= NTDDI_WIN2K)
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
VOID
KeAttachProcess(
	_Inout_ PRKPROCESS Process
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
VOID
KeDetachProcess(
	VOID
);
#endif
VOID* SSDT_Hook( VOID* OriginalFunction, VOID* NewFunction, ULONG* Index );
VOID SSDT_UnHook(PVOID func, ULONG ServiceId);
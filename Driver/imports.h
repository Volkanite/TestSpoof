NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass, 
    PVOID  SystemInformation, 
    ULONG  SystemInformationLength, 
    PULONG ReturnLength 
);
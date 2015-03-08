#include <ntddk.h>

#include "ntexapi.h"
#include "ssdt.h"
#include "imports.h"


/* 
 * Prototypes.
 */
 
typedef NTSTATUS (*TYPE_ZwQuerySystemInformation)(
    ULONG SystemInformationCLass,
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength
);

typedef NTSTATUS (*TYPE_ZwQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName, 
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, 
    PVOID KeyValueInformation, 
    ULONG Length, 
    PULONG ResultLength
);
    
    
TYPE_ZwQuerySystemInformation   Hooks_ZwQuerySystemInformation = NULL;
TYPE_ZwQueryValueKey            Hooks_ZwQueryValueKey = NULL;

ULONG Hooks_ZwQuerySystemInformation_Index;
ULONG Hooks_ZwQueryValueKey_Index;


typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
}SYSTEM_CODEINTEGRITY_INFORMATION;


NTSTATUS ZwQuerySystemInformation_Hook(
    ULONG SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength
    )
{ 
    NTSTATUS status;
    
    // Call old function.
    status = Hooks_ZwQuerySystemInformation(
        SystemInformationClass, 
        SystemInformation, 
        SystemInformationLength, 
        ReturnLength
        );
     
    // New instructions.
    
    if (SystemInformationClass == SystemCodeIntegrityInformation)
    {
        SYSTEM_CODEINTEGRITY_INFORMATION *integrityInformation = SystemInformation;
        
        DbgPrint("[TESTSPOOF] SYSTEM_CODEINTEGRITY_INFORMATION::CodeIntegrityOptions = %i\r\n",
            integrityInformation->CodeIntegrityOptions
            );
        
        // Set to 'test-signing NOT enabled'.
        integrityInformation->CodeIntegrityOptions = 1;
    }
    
    return status;
}


NTSTATUS ZwQueryValueKey_Hook(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName, 
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, 
    PVOID KeyValueInformation, 
    ULONG Length, 
    PULONG ResultLength
    )
{
    NTSTATUS status;
    
    // Call old function.
    status = Hooks_ZwQueryValueKey(
        KeyHandle,
        ValueName, 
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength
        );
    
    // New instructions.
    
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    
    if (KeyValueInformationClass == KeyValuePartialInformation)
    {
        KEY_VALUE_PARTIAL_INFORMATION *valueInformation;
        
        valueInformation = KeyValueInformation;
        
        // We are looking for the value BcdLibraryBoolean_AllowPrereleaseSignatures which can be found here:
        // HKEY_LOCAL_MACHINE\BCD00000000\Objects\{SOMEGUID}\Elements\16000049\Element
        // where {SOMEGUID} = BcdBootMgrObject_DefaultObject which can be found here:
        // HKEY_LOCAL_MACHINE\BCD00000000\Objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\Elements\23000003\Element
        // However due to share lazyness, i am just going to assume that any value that is REG_BINARY, that has a
        // data length of 1 and matches the name 'Element' is this value. Later someone can come and implement
        // this properly to avoid any false-positives but i think these heuristics should do the trick.
        
        if (valueInformation->Type == REG_BINARY
            && valueInformation->DataLength == 1
            && ValueName->Length == 14
            && wcsncmp(ValueName->Buffer, L"Element", ValueName->Length / sizeof(WCHAR)) == 0)
        {
            DbgPrint(
                "[TESTSPOOF] BcdLibraryBoolean_AllowPrereleaseSignatures = 0x%X\n", 
                valueInformation->Data[0]
                );
                
            // Set to 'test-signing NOT enabled'.
            valueInformation->Data[0] = 0x00;
        }
        
        // This one checks for HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemStartOptions.
        
        if (valueInformation->Type == REG_SZ
            && ValueName->Length == 36
            && wcsncmp(ValueName->Buffer, L"SystemStartOptions", ValueName->Length / sizeof(WCHAR)) == 0)
        {   
            DbgPrint("[TESTSPOOF] SystemStartOptions [%ws ]\n", (PWSTR) valueInformation->Data);
            
            // Here we'll just remove the "TESTSIGNING" part of the string.
            if (wcsncmp((PWSTR) valueInformation->Data, L" TESTSIGNING", 12) == 0)
            {
                WCHAR* buffer;
                ULONG numberOfCharacters;
                
                buffer = ExAllocatePoolWithTag( PagedPool, valueInformation->DataLength, 'SPOF' );
                numberOfCharacters = valueInformation->DataLength / sizeof(WCHAR);
                
                wcsncpy(buffer, (PWSTR) ((PWSTR) valueInformation->Data + 13), numberOfCharacters);
                wcsncpy((PWSTR) valueInformation->Data, buffer, numberOfCharacters);
                    
                ExFreePoolWithTag(buffer, 'SPOF'); 
            }
        }
    }
    
    return status;
}


VOID Hooks_Apply()
{
    Hooks_ZwQuerySystemInformation = (TYPE_ZwQuerySystemInformation) SSDT_Hook(
        (PULONG)ZwQuerySystemInformation, 
        (PULONG)ZwQuerySystemInformation_Hook,
        &Hooks_ZwQuerySystemInformation_Index
        );
        
    Hooks_ZwQueryValueKey = (TYPE_ZwQueryValueKey) SSDT_Hook( 
        (PULONG)ZwQueryValueKey,
        (PULONG)ZwQueryValueKey_Hook,
        &Hooks_ZwQueryValueKey_Index
        );
}


VOID Hooks_Remove()
{
    if (Hooks_ZwQuerySystemInformation != NULL) 
    {
        SSDT_UnHook(Hooks_ZwQuerySystemInformation, Hooks_ZwQuerySystemInformation_Index);
    }
    
    if (Hooks_ZwQueryValueKey != NULL)
    {
        SSDT_UnHook(Hooks_ZwQueryValueKey, Hooks_ZwQueryValueKey_Index);
    }
}
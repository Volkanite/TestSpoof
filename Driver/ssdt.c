#include <ntddk.h>
#include <ntimage.h>

#include "imports.h"
#include "ntexapi.h"


//structures
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
    LONG* ServiceTable;
    PVOID CounterTable;
#ifdef _WIN64
    ULONGLONG NumberOfServices;
#else
    ULONG NumberOfServices;
#endif
    PCHAR ArgumentTable;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

#pragma pack(push,1)
typedef struct _HOOKOPCODES
{
#ifdef _WIN64
    unsigned short int mov;
#else
    unsigned char mov;
#endif
    ULONG_PTR addr;
    unsigned char push;
    unsigned char ret;
}HOOKOPCODES;
#pragma pack(pop)

typedef struct _HOOKSTRUCT
{
    ULONG_PTR addr;
    HOOKOPCODES hook;
    unsigned char orig[sizeof(HOOKOPCODES)];
    //SSDT extension
    int SSDTindex;
    ULONG SSDTold;
    ULONG SSDTnew;
    ULONG_PTR SSDTaddress;
} HOOKSTRUCT, *HOOK;


//Based on: http://alter.org.ua/docs/nt_kernel/procaddr
PVOID KernelGetModuleBase(PCHAR pModuleName)
{
    ULONG i;
    
    typedef struct _SYSTEM_MODULE_ENTRY
    {
        ULONG Reserved1[2];
#ifdef _WIN64
        ULONG Reserved2[2];
#endif
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
    } SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
    typedef struct _SYSTEM_MODULE_INFORMATION
    {
        ULONG Count;
        SYSTEM_MODULE_ENTRY Module[0];
    } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

    PVOID pModuleBase = NULL;
    PULONG pSystemInfoBuffer = NULL;

    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONG    SystemInfoBufferSize = 0;

    status = ZwQuerySystemInformation(SystemModuleInformation,
        &SystemInfoBufferSize,
        0,
        &SystemInfoBufferSize
        );

    if (!SystemInfoBufferSize)
    {
        DbgPrint("[TESTSPOOF] ZwQuerySystemInformation (1) failed...\n");
        return NULL;
    }

    pSystemInfoBuffer = (PULONG)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

    if (!pSystemInfoBuffer)
    {
        DbgPrint("[TESTSPOOF] ExAllocatePool failed...\n");
        return NULL;
    }

    memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

    status = ZwQuerySystemInformation(SystemModuleInformation, pSystemInfoBuffer, SystemInfoBufferSize * 2, &SystemInfoBufferSize);

    if (NT_SUCCESS(status))
    {
        PSYSTEM_MODULE_ENTRY pSysModuleEntry = ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Module;
        ULONG len = (ULONG)strlen(pModuleName);
        
        for (i = 0; i < ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Count; i++)
        {
            if (_strnicmp(pSysModuleEntry[i].ImageName + pSysModuleEntry[i].ModuleNameOffset, pModuleName, len) == 0)
            {
                pModuleBase = pSysModuleEntry[i].Base;
                break;
            }
        }
    }
    else
        DbgPrint("[TESTSPOOF] ZwQuerySystemInformation (2) failed...\n");

    if (pSystemInfoBuffer)
    {
        ExFreePool(pSystemInfoBuffer);
    }

    return pModuleBase;
}


PVOID GetKernelBase()
{
    PVOID base = NULL;
    
    if (!base)
        base = KernelGetModuleBase("ntoskrnl");
    if (!base)
        base = KernelGetModuleBase("ntkrnlmp");
    if (!base)
        base = KernelGetModuleBase("ntkrnlpa");
    if (!base)
        base = KernelGetModuleBase("ntkrpamp");
        
    return base;
}


//Based on: https://code.google.com/p/volatility/issues/detail?id=189#c2
SYSTEM_SERVICE_DESCRIPTOR_TABLE* SSDT_Find()
{
    static SYSTEM_SERVICE_DESCRIPTOR_TABLE* SSDT = 0;
    
    if (!SSDT)
    {
        UNICODE_STRING routineName;
        PVOID KeASST;
        unsigned char function[1024];
        unsigned int function_size = 0;
        unsigned int i;
        int rvaSSDT = 0;
        
#ifndef _WIN64
        //x86 code
        RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
        SSDT = (SYSTEM_SERVICE_DESCRIPTOR_TABLE*)MmGetSystemRoutineAddress(&routineName);
#else
        //x64 code
        RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");
        
        KeASST = MmGetSystemRoutineAddress(&routineName);
        
        if (!KeASST)
        {
            DbgPrint("[TESTSPOOF] Failed to find KeAddSystemServiceTable!\n");
            return 0;
        }
        
        RtlCopyMemory(function, KeASST, sizeof(function));
        
        for (i = 0; i < sizeof(function); i++)
        {
            if (function[i] == 0xC3) //ret
            {
                function_size = i + 1;
                break;
            }
        }
        
        if (!function_size)
        {
            DbgPrint("[TESTSPOOF] Failed to get function size of KeAddSystemServiceTable!\n");
            return 0;
        }

        /*
        000000014050EA4A 48 C1 E0 05                shl rax, 5
        000000014050EA4E 48 83 BC 18 80 3A 36 00 00 cmp qword ptr [rax+rbx+363A80h], 0 <- we are looking for this instruction
        000000014050EA57 0F 85 B2 5C 0A 00          jnz loc_1405B470F
        000000014050EA5D 48 8D 8B C0 3A 36 00       lea rcx, rva KeServiceDescriptorTableShadow[rbx]
        000000014050EA64 48 03 C8                   add rcx, rax
        000000014050EA67 48 83 39 00                cmp qword ptr [rcx], 0
        */
        
        for (i = 0; i < function_size; i++)
        {
            if (((*(unsigned int*)(function + i)) & 0x00FFFFF0) == 0xBC8340 &&
                !*(unsigned char*)(function + i + 8)) //4?83bc?? ???????? 00 cmp qword ptr [r?+r?+????????h],0
            {
                rvaSSDT = *(int*)(function + i + 4);
                break;
            }
        }
        
        if (rvaSSDT) //this method worked
        {
            PVOID base;
            
            DbgPrint("[TESTSPOOF] SSDT RVA: 0x%X\n", rvaSSDT);
            
            base = GetKernelBase();
            
            if (!base)
            {
                DbgPrint("[TESTSPOOF] GetKernelBase() failed!\n");
                return 0;
            }
            
            DbgPrint("[TESTSPOOF] GetKernelBase()->0x%p\n", base);
            
            SSDT = (SYSTEM_SERVICE_DESCRIPTOR_TABLE*)((unsigned char*)base + rvaSSDT);
        }
        else
        {
            int rvaFound = -1;
            unsigned int i;
            
            /*
            Windows 10 Technical Preview:
            fffff800e21b30ec 757f             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
            fffff800e21b30ee 48833deafee4ff00 cmp qword ptr [nt!KeServiceDescriptorTable+0x20 (fffff800e2002fe0)],0 <- we are looking for this instruction
            fffff800e21b30f6 7575             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
            fffff800e21b30f8 48833da0fee4ff00 cmp qword ptr [nt!KeServiceDescriptorTableShadow+0x20 (fffff800e2002fa0)],0
            fffff800e21b3100 756b             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
            */
            
            for (i = 0; i < function_size; i++)
            {
                if (((*(unsigned int*)(function + i)) & 0x00FFFFFF) == 0x3D8348 &&
                    !*(unsigned char*)(function + i + 7)) //48833d ???????? 00 cmp qword ptr [X],0
                {
                    rvaFound = i;
                    rvaSSDT = *(int*)(function + i + 3);
                    break;
                }
            }
            if (rvaFound == -1)
            {
                DbgPrint("[TESTSPOOF] Failed to find pattern...\n");
                return 0;
            }
            //Sanity check SSDT & contents
            __try
            {
                ULONG_PTR check;
                
                SSDT = (SYSTEM_SERVICE_DESCRIPTOR_TABLE*)((ULONG_PTR)KeASST + rvaFound + rvaSSDT + 8 - 0x20);
                check = (ULONG_PTR)KeASST & 0xFFFFFFFF00000000;
                
                if (((ULONG_PTR)SSDT & 0xFFFFFFFF00000000) != check ||
                    ((ULONG_PTR)SSDT->ServiceTable & 0xFFFFFFFF00000000) != check ||
                    (SSDT->NumberOfServices & 0xFFFFFFFFFFFF0000) != 0 ||
                    ((ULONG_PTR)SSDT->ArgumentTable & 0xFFFFFFFF00000000) != check)
                {
                    DbgPrint("[TESTSPOOF] Found SSDT didn't pass all checks...\n");
                    return 0;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DbgPrint("[TESTSPOOF] An exception was thrown while accessing the SSDT...\n");
                return 0;
            }
        }
#endif
    }
    return SSDT;
}


VOID* InterlockedSet(LONG* Destination, LONG Source)
{
    LONG* Mapped;
    LONG result;
    
    //Change memory properties.
    PMDL g_pmdl = IoAllocateMdl(Destination, sizeof(LONG), 0, 0, NULL);
    
    if (!g_pmdl)
    {
        return;
    }
    
    MmBuildMdlForNonPagedPool(g_pmdl);
    
    Mapped = (LONG*)MmMapLockedPages(g_pmdl, KernelMode);
    
    if (!Mapped)
    {
        IoFreeMdl(g_pmdl);
        return;
    }
    
    result = InterlockedExchange(Mapped, Source);
    
    //Restore memory properties.
    MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
    IoFreeMdl(g_pmdl);
    
    return (VOID*) result;
}


int GetIndex( PUCHAR FunctionStart )
{
    int i;
    int SsdtOffset = -1;
    
    for (i = 0; i < 32 ; i++)
    {
        if (FunctionStart[i] == 0xC2 || FunctionStart[i] == 0xC3) //RET
            break;
        if (FunctionStart[i] == 0xB8) //mov eax,X
        {
            SsdtOffset = *(int*)(FunctionStart + i + 1);
            break;
        }
    }

    if (SsdtOffset == -1)
    {
        DbgPrint("[TESTSPOOF] SSDT Offset for not found...\n");
    }

    return SsdtOffset;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      Retrieve the Nt* address function given its syscall number in the SSDT
//  Parameters :
//      PULONG KiServiceTable : the SSDT base address
//      ULONG  ServiceId      : a syscall number
//  Return value :
//      ULONGLONG : the address of the function which has the syscall number given in argument
//  Process :
//      Because the addresses contained in the SSDT have the last four bits reserved to store the number of arguments,
//      in order to retrieve only the address, we shift four bits to the right
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
ULONGLONG GetNTAddressFromSSDT( PULONG KiServiceTable, ULONG ServiceId )
{
    return (LONGLONG)( KiServiceTable[ServiceId] >> 4 ) 
            + (ULONGLONG)KiServiceTable;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      Retrieve 12 bytes of free space in order to use that space as trampoline 
//  Parameters :
//      PUCHAR pStartSearchAddress : address where we will begin to search for 12 bytes of code cave
//  Return value :
//      PVOID : address of the code cave found
//  Process :
//      Search for 12 successive bytes at 0x00 from the address given in argument and returns the address found
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
PVOID searchCodeCave(PUCHAR pStartSearchAddress)
{
    #ifdef DEBUG
    KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "pStartSearchAddress : %llx\n", pStartSearchAddress));
    #endif
    
    while(pStartSearchAddress++)
    {       
        if(MmIsAddressValid(pStartSearchAddress))
        {
            if(*(PULONG)pStartSearchAddress == 0x00000000 && *(PULONG)(pStartSearchAddress+4) == 0x00000000 && *(PULONG)(pStartSearchAddress+8) == 0x00000000)
                return pStartSearchAddress-1;   
        }
    }
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Unsets WP bit of CR0 register (allows writing into SSDT).
//      See http://en.wikipedia.org/wiki/Control_register#CR0
//  Parameters :
//      None
//  Return value :
//      KIRQL : current IRQL value
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
KIRQL WPOFF( )
{
    KIRQL Irql = KeRaiseIrqlToDpcLevel();
    UINT_PTR cr0 = __readcr0();
      
    cr0 &= ~0x10000;
    __writecr0( cr0 );
    _disable();
  
    return Irql;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      Retrieve index of the Nt* function (given in parameter) in the SSDT
//  Parameters :
//      PULONG KiServiceTable : the SSDT address
//      PVOID FuncAddress     : a Nt* function address
//  Return value :
//      ULONG : the address which stores the Nt* function address (FuncAddress) in the SSDT
//  Process :
//      same as GetNtAddressFromSSDT() but in revert order
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
ULONG GetSSDTEntry(PULONG KiServiceTable, PVOID FuncAddress)
{
    return ((ULONG)((ULONGLONG)FuncAddress-(ULONGLONG)KiServiceTable)) << 4;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Sets WP bit of CR0 register.
//  Parameters :
//      None
//  Return value :
//      None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WPON(KIRQL Irql)
{
    UINT_PTR cr0 = __readcr0();
      
    cr0 |= 0x10000;
    _enable();  
    __writecr0( cr0 );
  
    KeLowerIrql( Irql );
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      Overwrite an entry of the SSDT by our trampoline (which jumps to our hooked Nt* function)
//  Parameters :
//      PVOID NewFunc    : Pointer to our hooked Nt* function
//      PVOID *OldFunc   : Pointer to which will point to the original Nt* function
//      LONG  ServiceId  : Syscall number of the function
//      PVOID searchAddr : Pointer to an address where we will begin to search for code cave
//      PVOID searchAddr : Pointer to an address where we will begin to search for code cave
//      PULONG KiServiceTable : Pointer to the SSDT
//  Return value :
//      PVOID : Returns a new base address which will be use to search for code cave
//  Process :
//      We want to overwrite an entry of the SSDT to our hooked function, but we can't do it directly because
//      the entries in the SSDT are not real address of the Nt* functions (see GetNTAddressFromSSDT() comments).
//      We will use the free space at the end of the .text section of the kernel as a trampoline. 
//      We can't directly write our trampoline in that space because it's not a writeable section, and we can't use
//      NtProtectVirtualMemory() because it only works in user-land. The trick (thx Ivanlef0u ;) is to create a 
//      Memory Descriptor List (MDL) with the new rights (RWX) pointing to the virtual address of the code cave space.
//      We can now write our trampoline (mov rax, @new func; jmp rax) and overwrite SSDT entry by the address of the 
//      trampoline.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID install_hook(PVOID NewFunc, PVOID* OldFunc, LONG ServiceId, PVOID searchAddr, PULONG KiServiceTable)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UCHAR jmp_to_newFunction[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0"; //mov rax, xxx ; jmp rax
    KIRQL Irql;
    ULONG SsdtEntry;
    PVOID trampoline;
    PMDL mdl;
    PVOID memAddr;

    *OldFunc = (PVOID)GetNTAddressFromSSDT(KiServiceTable, ServiceId); 
        
    #ifdef DEBUG
    KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "OldFunc : %llx\n", *OldFunc)); 
    #endif
    
    // mov rax, @NewFunc; jmp rax
    *(PULONGLONG)(jmp_to_newFunction+2) = (ULONGLONG)NewFunc;
    trampoline = searchCodeCave(searchAddr);
    
    #ifdef DEBUG
    KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "trampoline : %llx\n", trampoline));
    #endif
    
    mdl = IoAllocateMdl(trampoline, 12, FALSE, FALSE, NULL);
    if(mdl == NULL)
    {
        #ifdef DEBUG
        KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "IoAllocateMdl failed !!\n"));
        #endif
    }
    MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess); 
    memAddr = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if(memAddr == NULL)
    {
        #ifdef DEBUG
        KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "MmMapLockedPagesSpecifyCache failed !!\n"));   
        #endif
    }
    Irql = WPOFF();
    RtlMoveMemory(memAddr, jmp_to_newFunction, 12); 

    SsdtEntry = GetSSDTEntry(KiServiceTable, trampoline);
    SsdtEntry &= 0xFFFFFFF0;
    SsdtEntry += KiServiceTable[ServiceId] & 0x0F;      
    KiServiceTable[ServiceId] = SsdtEntry;   
    
    WPON( Irql );
    
    return (PVOID)((ULONG_PTR)trampoline+12);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Retrieve end address of the .text section of the module given in argument
//  Parameters :
//      PVOID moduleBase : base address of a module
//  Return value :
//      Returns end address of .text section of moduleBase
//  Process :
//      Parse module base PE header to get the number of sections and to retrieve section header address,
//      then parse each section and when we get to the .text section, returns address of the end of the section
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID getEndOfTextSection(PVOID moduleBase)
{
    USHORT NumberOfSections;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS64 pNtHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    ULONG i;
    PVOID begin_text, end_text;
    
    pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    pNtHeader = (PIMAGE_NT_HEADERS)((unsigned char*)moduleBase+pDosHeader->e_lfanew);
    
    NumberOfSections = pNtHeader->FileHeader.NumberOfSections;
    #ifdef DEBUG
    KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "Number of Sections: %d\n", NumberOfSections));
    #endif

    pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char*)pNtHeader+sizeof(IMAGE_NT_HEADERS64));
    #ifdef DEBUG
    KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "section header : %llx \n", pSectionHeader));
    #endif
    
    // parse each section in order to get to the executable section 
    for(i=0; i<NumberOfSections; i++)
    {
        // this is the .text section
        if(pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            begin_text = (PVOID)(pSectionHeader->VirtualAddress + (ULONG_PTR)moduleBase);
            end_text = (PVOID)((ULONG_PTR)begin_text + pSectionHeader->Misc.VirtualSize);
            #ifdef DEBUG
            KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "%s section is located at : %llx \n", pSectionHeader->Name, begin_text));
            KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "end of %s section at : %llx \n", pSectionHeader->Name, end_text));
            #endif
            break;
        }
        pSectionHeader++;
    }
    return end_text;
}


VOID* SSDT_Hook( VOID* OriginalFunction, VOID* NewFunction, ULONG* Index )
{
    SYSTEM_SERVICE_DESCRIPTOR_TABLE *SSDT;
    ULONG_PTR SSDTbase;
    ULONG serviceIndex;
    ULONG oldValue;
    ULONG newValue;
    VOID* result;
    static ULONG CodeSize = 0;
    static PVOID CodeStart = 0;
    PVOID CaveAddress;
    PVOID returnCall64;
    static PVOID startSearchAddress = NULL;
    
    SSDT = SSDT_Find();
    
    if (!SSDT)
    {
        DbgPrint("[TESTSPOOF] SSDT not found...\n");
        return 0;
    }
    
    SSDTbase = (ULONG_PTR)SSDT->ServiceTable;
    
    if (!SSDTbase)
    {
        DbgPrint("[TESTSPOOF] ServiceTable not found...\n");
        return 0;
    }

    serviceIndex = GetIndex((PUCHAR)OriginalFunction);
    *Index = serviceIndex;

    DbgPrint("[TESTSPOOF] serviceIndex = %u", serviceIndex);
    
    if (serviceIndex == -1)
    {
        return 0;
    }
    
    if (serviceIndex >= SSDT->NumberOfServices)
    {
        DbgPrint("[TESTSPOOF] Invalid API offset...\n");
        return 0;
    }

    oldValue = SSDT->ServiceTable[serviceIndex];
    
#ifdef _WIN64
    /*
    x64 SSDT Hook;
    1) find API addr
    2) get code page+size
    3) find cave address
    4) hook cave address (using hooklib)
    5) change SSDT value
    */
    
    if (!startSearchAddress)
    {
        startSearchAddress = getEndOfTextSection(GetKernelBase());
    }

    startSearchAddress = install_hook((PVOID)NewFunction, &returnCall64, serviceIndex, startSearchAddress, SSDTbase);
    
    return returnCall64;

#else
    /*
    x86 SSDT Hook:
    1) change SSDT value
    */
    newValue = (ULONG)NewFunction;
    result = InterlockedSet(&SSDT->ServiceTable[serviceIndex], newValue);
    DbgPrint("[TESTSPOOF] SSDThook(0x%p, 0x%p)\n", oldValue, newValue);

    return result;
#endif    
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Restore SSDT
//  Parameters :
//      PVOID func : address of original Nt* function
//      ULONG ServiceId : func syscall number
//  Return value :
//      None
//  Process :
//      restore SSDT by overwriting SSDT entries which were altered by the original ones
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID SSDT_UnHook(PVOID func, ULONG ServiceId)
{
    KIRQL Irql;
    ULONG SsdtEntry;
    SYSTEM_SERVICE_DESCRIPTOR_TABLE *systemServiceDescriptorTable;
    
    systemServiceDescriptorTable = SSDT_Find();
    
    Irql = WPOFF();
    
    SsdtEntry = GetSSDTEntry(systemServiceDescriptorTable->ServiceTable, func);
    SsdtEntry &= 0xFFFFFFF0;
    SsdtEntry += systemServiceDescriptorTable->ServiceTable[ServiceId] & 0x0F;
    
    systemServiceDescriptorTable->ServiceTable[ServiceId] = SsdtEntry;
    
    WPON(Irql);
}
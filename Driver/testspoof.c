#include <ntddk.h>
#include "hooks.h"


/* Function Prototypes */
NTSTATUS TestSpoof_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID TestSpoof_Unload(PDRIVER_OBJECT  DriverObject);  
  
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  pDriverObject, 
    PUNICODE_STRING  pRegistryPath
    );

/* Compile directives. */
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, TestSpoof_Unload)
#pragma alloc_text(PAGE, TestSpoof_UnSupportedFunction)


/*
 * DriverEntry: entry point for drivers.
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    unsigned int uiIndex = 0;
    PDEVICE_OBJECT pDeviceObject = NULL;
    UNICODE_STRING usDriverName, usDosDeviceName;

    DbgPrint("DriverEntry Called \r\n");

    RtlInitUnicodeString(&usDriverName, L"\\Device\\TestSpoof");
    RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\TestSpoof"); 

    NtStatus = IoCreateDevice(
        pDriverObject, 
        0, 
        &usDriverName, 
        FILE_DEVICE_UNKNOWN, 
        FILE_DEVICE_SECURE_OPEN, 
        FALSE, 
        &pDeviceObject
        );

    if(NtStatus == STATUS_SUCCESS) {
        /* MajorFunction: is a list of function pointers for entry points into the 
        driver. */
        for(uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
             pDriverObject->MajorFunction[uiIndex] = TestSpoof_UnSupportedFunction;

             
        /* DriverUnload is required to be able to dynamically unload the driver. */
        pDriverObject->DriverUnload =  TestSpoof_Unload; 
        pDeviceObject->Flags |= 0;
        pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
        
        /* Create a Symbolic Link to the device. TestSpoof -> \Device\TestSpoof */
        IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
        
        // Initialize Hooks.
        Hooks_Apply();
    }

    return NtStatus;
}


 /*
  * TestSpoof_Unload: called when the driver is unloaded.
  */
VOID TestSpoof_Unload(PDRIVER_OBJECT  DriverObject) {
    /* local variables */
    UNICODE_STRING usDosDeviceName;

    // Unhook and restore hooked functions.
    Hooks_Remove();
    
DbgPrint("The original SSDT function restored.\r\n");
    /* delete the driver */
    DbgPrint("TestSpoof_Unload Called \r\n");
    RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\TestSpoof");
    IoDeleteSymbolicLink(&usDosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}


/*
 * TestSpoof_UnSupportedFunction: called when a major function is issued that isn't 
 * supported.
 */
NTSTATUS TestSpoof_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
    DbgPrint("TestSpoof_UnSupportedFunction Called \r\n");

    return NtStatus;
}
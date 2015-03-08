#include <sl.h>
#include <string.h>
#include <sltray.h>
#include <slresource.h>


#define SERVICE_CONTROL_STOP 0x00000001


int __stdcall WinMain( 
    VOID* Instance, 
    VOID *hPrevInstance, 
    CHAR *pszCmdLine, 
    INT32 iCmdShow 
    )
{
    HANDLE hSCManager = NULL;
    HANDLE hService = NULL;
    SERVICE_STATUS  serviceStatus;

    SlExtractResource(
        L"DRIVER", 
        L"testspoof.sys"
        );

    SlLoadDriver(
        L"TESTSPOOF",
        L"testspoof.sys",
        L"TestSpoof Kernel-Mode Driver",
        NULL,
        FALSE,
        NULL
        );

    SlTrayMinimize(
        NULL,
        LoadIconW(Instance, L"TS_ICON"),
        L"TestSpoof",
        NULL,
        NULL,
        NULL
        );

    SlHandleMessages();
    
    hSCManager = OpenSCManagerW(
        NULL, 
        NULL, 
        SC_MANAGER_ALL_ACCESS
        );

    hService = OpenServiceW(
        hSCManager, 
        L"TESTSPOOF", 
        SERVICE_ALL_ACCESS
        );
    
    ControlService(
        hService, 
        SERVICE_CONTROL_STOP, 
        &serviceStatus
        );
        
    CloseServiceHandle(hService);

    return 0;
}




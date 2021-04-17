#include <Windows.h>
#include <iostream>
#include <sstream>
#include <string_view>

typedef LONG NTSTATUS;
#define NT_STATUS(x)        (((NTSTATUS)(x)) >= 0)
#define NT_INFORMATION(x)   ((((ULONG)(x)) >> 30) == 1)
#define NT_WARNING(x)       ((((ULONG)(x)) >> 30) == 2)
#define NT_ERROR(x)         ((((ULONG)(x)) >> 30) == 3)

auto constexpr servicePath = L"C:\\Users\\user\\source\\repos\\HelloDriver\\x64\\Debug\\HelloDriver.sys";
auto constexpr serviceName = L"my_driver";

auto Error(const std::string_view &error)
{
    auto error_code = GetLastError();
    auto error_desc = std::system_category().message(error_code);
    std::ostringstream oss;
    oss << std::hex << error_code;
    std::cerr << "0x" << oss.str() << ": " << error_desc << std::endl;
    std::cerr << error << std::endl;
    return error_code;
}

int legit_load()
{
    auto SCManagerHandle = OpenSCManager(
        NULL,
        NULL,
        SC_MANAGER_ALL_ACCESS
    );
    if (!SCManagerHandle)
        return Error("Cannot open services manager");

    std::cout << "Create service" << std::endl;
    auto SCHandle = CreateService(
        SCManagerHandle,
        serviceName,
        serviceName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, // SERVICE_BOOT_START, SERVICE_AUTO_START, SERVICE_SYSTEM_START
        SERVICE_ERROR_NORMAL, // SERVICE_ERROR_IGNORE
        servicePath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    if (!SCHandle)
    {
        CloseServiceHandle(SCManagerHandle);
        return Error("Cannot create the service");
    }

    std::cout << "Open service" << std::endl;
    SCHandle = OpenService(
        SCManagerHandle,
        serviceName,
        SERVICE_ALL_ACCESS
    );
    if (!SCHandle)
    {
        CloseServiceHandle(SCManagerHandle);
        return Error("Cannot open the service");
    }

    if (StartService(SCHandle, 0, NULL) == 0)
    {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        {

            return Error("Cannot start the service");
        }
    }

    std::cout << "Wait..." << std::endl;
    Sleep(5000);

    std::cout << "Stop service" << std::endl;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    ControlService(
        SCHandle,
        SERVICE_CONTROL_STOP,
        (LPSERVICE_STATUS)&ssp
    );

    while (ssp.dwCurrentState != SERVICE_STOPPED)
    {
        Sleep(1000);
        auto ok = QueryServiceStatusEx(
            SCHandle,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded
        );
        if (!ok)
        {
            CloseServiceHandle(SCHandle);
            CloseServiceHandle(SCManagerHandle);
            return Error("Cannot query service status");
        }
    }

    std::cout << "Delete service" << std::endl;
    DeleteService(SCHandle);

    CloseServiceHandle(SCHandle);
    CloseServiceHandle(SCManagerHandle);
    return 0;
}

constexpr auto SystemExtendedServiceTableInformation = 38;

typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PVOID   Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE {
    UNICODE_STRING ModuleName;
} SYSTEM_LOAD_AND_CALL_IMAGE;

void(CALLBACK* RtlInitUnicodeString)
(
    IN OUT UNICODE_STRING*  DestinationString,
    IN PCWSTR               SourceString
);
typedef void(CALLBACK* RTLINITUNICODESTRING) (UNICODE_STRING*, PCWSTR);

NTSTATUS(CALLBACK* ZwSetSystemInformation)
(
    IN DWORD        functionCode,
    IN OUT PVOID    driverName,
    IN LONG         driverNameLength
);
typedef NTSTATUS(CALLBACK* ZWSETSYSTEMINFORMATION) (DWORD, PVOID, LONG);

int funky_load(void)
{
    /*
    ZwSetSystemInformation
    SystemExtendedServiceTableInformation (0x26 - 38)

    The information buffer must provide exactly a UNICODE_STRING structure.
    This is to name a driver to load as a per-session system image and to initialise as the session driver.
    If executing for a user-mode request, the permitted circumstancesand the freedom to name the driver are greatly restricted.
    Failure on any count causes the function to return STATUS_PRIVILEGE_NOT_HELD.
    First, the current process must be the session master.
    Second, the caller must have SeLoadDriverPrivilege.
    Third, the name can only be \SystemRoot\System32\win32k.sys, as 0x3E bytes in this particular mixture of case.

    With these requirements all met, the function reissues itself as a kernel-mode ZwSetSystemInformation
    */

    SYSTEM_LOAD_AND_CALL_IMAGE image;
    UNICODE_STRING str;

    auto handle = GetModuleHandle(L"ntdll.dll");
    if (!handle)
        return Error("Cannot get ntdll.dll");

    ZwSetSystemInformation = (ZWSETSYSTEMINFORMATION)GetProcAddress(handle, "ZwSetSystemInformation");
    if (!ZwSetSystemInformation)
        return Error("Cannot get ZwSetSystemInformation");

    RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(handle, "RtlInitUnicodeString");
    if (!RtlInitUnicodeString)
        return Error("Cannot get RtlAnsiStringToUnicodeString");

    RtlInitUnicodeString(&(image.ModuleName), servicePath);
    ZwSetSystemInformation(SystemExtendedServiceTableInformation, &image, sizeof(SYSTEM_LOAD_AND_CALL_IMAGE));
    return Error("ZwSetSystemInformation");
}

int main(int argc, WCHAR **argv)
{
    return legit_load();
}

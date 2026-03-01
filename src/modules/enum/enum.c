#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>
#include <wchar.h>
#include <winternl.h>
#include <util/util.h>

typedef NTSTATUS(NTAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

int def_enum(LPCWSTR gProcName, DWORD *PID, HANDLE *phProcess)
{
  DWORD lPrcsID[1024 * 2], cb = sizeof(lPrcsID), dwReturnLen1 = 0, dwReturnLen2 = 0;
  DWORD dwPIDNums = 0;
  DWORD dwDesiredAccess = PROCESS_ALL_ACCESS;
  HANDLE hProcess = NULL;
  HMODULE hModule = NULL;
  WCHAR ProcName[MAX_PATH];
  *PID = 0;
  *phProcess = NULL;

  if (EnumProcesses(lPrcsID, cb, &dwReturnLen1) == 0)
  {
    warn("EnumProcesses failed: %d", GetLastError());
    return -1; // Error in EnumProcesses
  }
  dwPIDNums = dwReturnLen1 / sizeof(DWORD);
  for (DWORD i = 0; i < dwPIDNums; i++)
  {
    if (lPrcsID[i] != 0)
    {
      hProcess = OpenProcess(dwDesiredAccess, FALSE, lPrcsID[i]);
      if (hProcess != NULL)
      {
        if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2))
        {
          warn("EnumProcessModules failed at PID %lu with error %lu", lPrcsID[i], GetLastError());
          CloseHandle(hProcess);
          continue;
        }
        if (!GetModuleBaseNameW(hProcess, hModule, ProcName, sizeof(ProcName) / sizeof(WCHAR)))
        {
          warn("GetModuleBaseName failed for PID %lu with error code %lu", lPrcsID[i], GetLastError());
          CloseHandle(hProcess);
          continue;
        }
        if (wcsicmp(gProcName, ProcName) == 0)
        {
          okay("Found process %ls of PID %lu", ProcName, lPrcsID[i]);
          *PID = lPrcsID[i];
          *phProcess = hProcess;
          return 0;
        }
        CloseHandle(hProcess);
      }
    }
  }
  warn("Either the process ID or the process handle got returned as NULL");
  return -1;
}

int ntQuery_enum(LPCWSTR gProcName, DWORD *PID, HANDLE *phProcess)
{
  PFN_NT_QUERY_SYSTEM_INFORMATION pNtQuerySystemInformation = NULL;
  ULONG uReturnLen1 = 0, uReturnLen2 = 0;
  PSYSTEM_PROCESS_INFORMATION SysProcInfo = NULL, pCurrent = NULL;
  NTSTATUS STAT = 0;
  HANDLE hProcess = NULL;

  *PID = 0;
  *phProcess = NULL;

  // Get function pointer
  // If you want to improve this, replace the GetProcAddress with HellsGate
  pNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
  if (!pNtQuerySystemInformation)
  {
    warn("GetProcAddress failed to get NtQuerySystemInformation: %d", GetLastError());
    return -1;
  }

  // First call to get required buffer size
  STAT = pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);
  if (STAT != STATUS_INFO_LENGTH_MISMATCH)
  {
    warn("NtQuerySystemInformation (size query) failed: 0x%08X", STAT);
    return -1;
  }

  SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(uReturnLen1);
  if (!SysProcInfo)
  {
    warn("malloc failed for SysProcInfo");
    return -1;
  }
  memset(SysProcInfo, 0, uReturnLen1);

  STAT = pNtQuerySystemInformation(SystemProcessInformation, SysProcInfo, uReturnLen1, &uReturnLen2);
  if (STAT != 0)
  {
    warn("NtQuerySystemInformation failed with status: 0x%08X", STAT);
    free(SysProcInfo);
    return -1; // Error in NtQuerySystemInformation
  }

  /* Important parts within the struct we need:
  typedef struct _SYSTEM_PROCESS_INFORMATION {
      ULONG NextEntryOffset;
      ...
      UNICODE_STRING ImageName;
      ...
      HANDLE UniqueProcessId;
      ...
  } SYSTEM_PROCESS_INFORMATION;*/

  // Iterate through the process information
  pCurrent = SysProcInfo;
  while (1)
  {
    if (pCurrent->ImageName.Buffer != NULL)
    {
      // Compare the process name with the target process name
      if (wcsicmp(gProcName, pCurrent->ImageName.Buffer) == 0)
      {
        *PID = (DWORD)(ULONG_PTR)pCurrent->UniqueProcessId;
        *phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
        if (*phProcess == NULL)
        {
          warn("OpenProcess failed for PID %lu: %d", *PID, GetLastError());
          free(SysProcInfo);
          return -1; // Error in OpenProcess
        }
        okay("Found process %ls with PID %lu", gProcName, *PID);
        free(SysProcInfo);
        return 0; // Success
      }
    }
    if (pCurrent->NextEntryOffset == 0)
      break;
    pCurrent = (PSYSTEM_PROCESS_INFORMATION)((BYTE *)pCurrent + pCurrent->NextEntryOffset);
  }
  free(SysProcInfo);
  warn("Process %ls not found", gProcName);
  return -1; // Process not found
}

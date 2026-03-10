#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <stdbool.h>
#include <util/util.h>

bool protect_process(HANDLE hProcess)
{

  ULONG SecDescSize = 0;
  DWORD StringSDRevision = SDDL_REVISION_1;
  PVOID pSecDesc = NULL;
  // Declare sec descripter string
  // 'D": Deny access to everyone to object and its children
  // 'A': Allow access to local system and proc owner
  LPCWSTR sddlString = L"D:P(D;OICI;GA;;;WD)(A;OICI;GA;;;SY)(A;OICI;GA;;;OW)";
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddlString, StringSDRevision, &pSecDesc, &SecDescSize))
  {
    warn("Failed to setup security descriptor, error is: %d", GetLastError());
    return false;
  }
  if (SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, pSecDesc) == 0)
  {
    warn("Failed to change security descriptor, error is: %d", GetLastError());
    return false;
  }
  okay("Changed security descriptor");

  return true;
}

bool ExecDelay(int ftMinutes)
{

  DWORD dwMilliSeconds = ftMinutes * 60000;
  HANDLE hEvent = CreateEvent(NULL, 0, 0, NULL);

  // Needed to verify delay as environments may fast forward
  DWORD T0 = GetTickCount64();

  info("Sleeping...");
  if (WaitForSingleObject(hEvent, dwMilliSeconds) == WAIT_FAILED)
  {
    fail("Execution delay timed out");
    return false;
  }
  DWORD T1 = GetTickCount64();

  info("Woke up...");
  if ((DWORD)(T1 - T0) < dwMilliSeconds)
    return false;
  else
    return true;
}

bool IsDebugged()
{

  DWORD dwTime1 = 0, dwTime2 = 0;
  dwTime1 = GetTickCount64();

  CONTEXT Ctx = {.ContextFlags = CONTEXT_DEBUG_REGISTERS};
  // Custom is DbgPresent
#ifdef _WIN64
  PPEB pPeb = (PEB *)(__readgsqword(0x60));
#elif _WIN32
  PPEB pPeb = (PEB *)(__readfsdword(0x30));
#endif
  if (pPeb->BeingDebugged == 1)
    return true;
  // Check debugging via HwBp
  if (!GetThreadContext(GetCurrentThread(), &Ctx))
  {
    fail("GetThreadContext failed: %d", GetLastError());
    return false;
  }
  // Check hardware breakpoints
  if (Ctx.Dr0 != 0 || Ctx.Dr1 != 0 || Ctx.Dr2 != 0 || Ctx.Dr3 != 0)
  {
    return true;
  }

  dwTime2 = GetTickCount64();
  info("Debug check took %d ms", dwTime2 - dwTime1);
  // If the check took too long, assume we are debugged
  if ((DWORD)(dwTime2 - dwTime1) > 50)
  {
    return true;
  }

  return false;
}
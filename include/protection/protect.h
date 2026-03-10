#ifndef PROTECT_H
#define PROTECT_H

#ifdef PROTECT
bool protect_process(HANDLE hProcess);
#endif
#ifdef TARGET_PROC_EXEC_DELAY
bool ExecDelay(int ftMinutes);
#endif
#ifdef ANTIDEBUG
bool IsDebugged();
#endif
#endif
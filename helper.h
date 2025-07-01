#ifndef HELPER_H
#define HELPER_H

#include <windows.h>
#include <stdlib.h>

#define MAX_URL 2048
#define MAX_FILE 255
#define MAX_REG_KEY_NAME 255
#define MAX_REG_VALUE_NAME 16383

#define WIN_ERROR 0x0
#define CONTINUE_ERROR 0x1 
#define FAIL_ERROR 0x2
#define SUCCESS 0x3

VOID TranslateErrorPrintImpl(DWORD errCode, const char *file, int line);
VOID TranslateErrorPrintImplStr(const char *errMsg, const char *file, int line);

#define TranslateErrorPrint(errCode) TranslateErrorPrintImpl(errCode, __FILE__, __LINE__);
#define TranslateErrorPrintStr(errMsg) TranslateErrorPrintImplStr(errMsg, __FILE__, __LINE__);
                
typedef int (*ValidatorFunc)(char *arg, void *data);

BOOL printHelp = TRUE;
static BOOL shutdownFlag = FALSE;

VOID TranslateError(DWORD errCode, char **pErrMessage) {
	FormatMessageA(
	    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	    NULL,
	    errCode,
	    0,
	    (LPSTR)pErrMessage,
	    0,
	    NULL);
}

VOID TranslateErrorPrintImplStr(const char* errMsg, const char *file, int line) {
    fprintf(stderr, "[-] ERROR at %s:%d: %s", file, line, errMsg);
}

VOID TranslateErrorPrintImpl(DWORD errCode, const char *file, int line) {
    char* errMsg;
    TranslateError(errCode, &errMsg);
    fprintf(stderr, "[-] ERROR at %s:%d: %lu - %s", file, line, errCode, errMsg);
    LocalFree(errMsg);
}

BOOL ExecuteCommand(const char* command) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    int commandLen = strlen(command);
    char execCmdCopy[commandLen + 16];
    const char* cmd = "cmd.exe /C ";

    int cmdLen = strlen(cmd);
    memcpy(execCmdCopy, cmd, cmdLen);

    memcpy(execCmdCopy + cmdLen, command, commandLen);
    execCmdCopy[cmdLen + commandLen] = '\0';

    printf("[!] Executing: %s\n", execCmdCopy);

    BOOL rc = CreateProcessA(
        NULL,
        (LPSTR) execCmdCopy,
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );

    if (rc == FALSE) {
        TranslateErrorPrint(GetLastError());
        return FALSE;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Check exit exit code
    DWORD exitCode = 0;
    if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
        TranslateErrorPrint(GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (exitCode != 0) {
        printf("[-] Command failed to execute (%lu). Try another option.\n", exitCode);
        return FALSE;
    }

    return TRUE;
}

BOOL LocateBinary(char *binaryPath, const char *binary, DWORD binaryPathSize) {
    DWORD rc = SearchPathA(
        NULL,
        binary,
        NULL,
        binaryPathSize,
        binaryPath,
        NULL
    );

    if (!rc) {
        printf("[-] Binary %s not found!\n", binary);
    }
    
    return rc;
}

BOOL PromptUntilValid(const char *prompt, char* buffer, size_t bufferSize, ValidatorFunc validator, void *data, BOOL allowDefault) {
    int rc;
    puts("");
    while (!shutdownFlag) {
        printf("TIE-Bomber(%s) > ", prompt);
        fflush(stdout);
        fgets(buffer, (int)bufferSize, stdin);
        buffer[strcspn(buffer, "\n")] = '\0';
        if (*buffer == '\0' && allowDefault == FALSE) {
            continue;
        }
        if (strcmp(buffer, "q") == 0 || strcmp(buffer, "quit") == 0 || strcmp(buffer, "exit") == 0 || strcmp(buffer, "no") == 0 || strcmp(buffer, "n") == 0) {
                printf("\n[*] Exiting...\n");
                shutdownFlag = TRUE;
                return FALSE;
        }
        if (validator && strcmp(buffer, "h") == 0) {
            printHelp = TRUE;
        }
        
        if (!validator) {
            if (strcmp(buffer, "y") == 0 || strcmp(buffer, "yes") == 0) {
                break;
            }
            continue;   
        }    

        rc = validator(buffer, data);
        if (rc == WIN_ERROR) {
            TranslateErrorPrint(GetLastError());
            continue;
        } else if (rc == FAIL_ERROR) { 
            break;
        } else if (rc == CONTINUE_ERROR) {
            continue;
        }
        break;
    }
    puts("");
    return TRUE;
}


#endif // HELPER_H

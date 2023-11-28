#include <Windows.h>h
#include <stdio.h>
#include <shlwapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "shlwapi.lib")

int main(int argc, char** argv) {

	if (argc < 2) {

		printf("%s enables the requested privilege in its parent process: the shell calling it\n", argv[0]);
		printf("Usage: %s <privilege_number>\n\nPrivilege list: (source https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_privilege.h)\n", argv[0]);
		printf("SE_CREATE_TOKEN             2\n\
SE_ASSIGNPRIMARYTOKEN       3\n\
SE_LOCK_MEMORY              4\n\
SE_INCREASE_QUOTA           5\n\
SE_UNSOLICITED_INPUT        6\n\
SE_TCB                      7\n\
SE_SECURITY                 8\n\
SE_TAKE_OWNERSHIP           9\n\
SE_LOAD_DRIVER              10\n\
SE_SYSTEM_PROFILE           11\n\
SE_SYSTEMTIME               12\n\
SE_PROF_SINGLE_PROCESS      13\n\
SE_INC_BASE_PRIORITY        14\n\
SE_CREATE_PAGEFILE          15\n\
SE_CREATE_PERMANENT         16\n\
SE_BACKUP                   17\n\
SE_RESTORE                  18\n\
SE_SHUTDOWN                 19\n\
SE_DEBUG                    20\n\
SE_AUDIT                    21\n\
SE_SYSTEM_ENVIRONMENT       22\n\
SE_CHANGE_NOTIFY            23\n\
SE_REMOTE_SHUTDOWN          24\n\
SE_UNDOCK                   25\n\
SE_SYNC_AGENT               26\n\
SE_ENABLE_DELEGATION        27\n\
SE_MANAGE_VOLUME            28\n\
SE_IMPERSONATE              29\n\
SE_CREATE_GLOBAL            30\n\
SE_TRUSTED_CREDMAN_ACCESS   31\n\
SE_RELABEL                  32\n\
SE_INC_WORKING_SET          33\n\
SE_TIME_ZONE                34\n\
SE_CREATE_SYMBOLIC_LINK     35\n");
		return -1;

	}
	
	int iPrivId = 0;
	int iRet = 0;
	HANDLE hToken = NULL;
	HANDLE hParentProcess = NULL;
	TOKEN_PRIVILEGES sctTokPriv = { 0 };
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32W sctPe32 = { 0 };
	sctPe32.dwSize = sizeof(PROCESSENTRY32W);
	DWORD dwCurrentPid = GetCurrentProcessId();
	DWORD dwParentPid = 0;


	if (!StrToIntExA(argv[1], STIF_DEFAULT, &iPrivId) || iPrivId < 2 || iPrivId > 35) {

		printf("[-] Invalid privilege id: %s\n", argv[1]);
		iRet = -1; goto _EndOfFunc;

	}

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {

		printf("[-] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		iRet = -1; goto _EndOfFunc;
	}

	if (Process32First(hSnapshot, &sctPe32)) {

		do {
			if (sctPe32.th32ProcessID == dwCurrentPid) {
				dwParentPid = sctPe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &sctPe32));

	}
	else {

		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		iRet = -1; goto _EndOfFunc;

	}

	if (dwParentPid == 0) {

		printf("[-] Could not find parent PID\n");
		iRet = -1; goto _EndOfFunc;

	}

	hParentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwParentPid);
	if (hParentProcess == NULL) {

		printf("[-] Error opening parent process with PROCESS_QUERY_LIMITED_INFORMATION: %d\n", GetLastError());
		iRet = -1; goto _EndOfFunc;

	}

	if (!OpenProcessToken(hParentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {

		printf("[-] Error opening parent process token with TOKEN_ADJUST_PRIVILEGES: %d\n", GetLastError());
		iRet = -1; goto _EndOfFunc;

	}

	sctTokPriv.PrivilegeCount = 1;
	sctTokPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	sctTokPriv.Privileges[0].Luid.LowPart = iPrivId;
	sctTokPriv.Privileges[0].Luid.HighPart = 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &sctTokPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {

		printf("[-] Error adjusting token privilege: %d\n", GetLastError());
		iRet = -1; goto _EndOfFunc;

	}
	else if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {

		printf("[-] Current token does not have the requested privilege\n");
		iRet = -1; goto _EndOfFunc;

	}

	printf("[+] Success enabling requested privilege!\n");

_EndOfFunc:
	if(hParentProcess && hParentProcess != INVALID_HANDLE_VALUE)
		CloseHandle(hParentProcess);
	if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);
	if (hToken && hToken != INVALID_HANDLE_VALUE)
		CloseHandle(hToken);

	return iRet;

}

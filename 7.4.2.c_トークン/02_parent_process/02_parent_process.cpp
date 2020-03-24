#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

PSID GetUserSidFromToken(HANDLE hToken);
DWORD GetParentProcessId();

// 現在のプロセスのトークンユーザーが親プロセスと同一であることを確認

int main()
{
	HANDLE hProcess;
	DWORD  dwParentProcessId = GetParentProcessId();

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwParentProcessId);
	if (hProcess == NULL) {
		printf("親プロセスのハンドルを取得できない %d", GetLastError());
		return -1;
	}

	HANDLE hToken, hTokenParent;
	PSID   pSid, pSidParent;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	OpenProcessToken(hProcess, TOKEN_QUERY, &hTokenParent);
	pSid = GetUserSidFromToken(hToken);
	pSidParent = GetUserSidFromToken(hTokenParent);

	int nExitCode = -1;
	if (EqualSid(pSid, pSidParent)) {
		printf("SIDは親と一致している");
#if 0
		WCHAR  szParentFilePath[MAX_PATH];
		DWORD  dwSize = MAX_PATH;
		QueryFullProcessImageName(hProcess, 0, szParentFilePath, &dwSize);
		printf("親プロセス : %ws\n", szParentFilePath);
#endif
		nExitCode = 0;
	}
	else {
		printf("トークンが伝播していない");
	}

	LocalFree(pSid);
	LocalFree(pSidParent);
	CloseHandle(hProcess);
	CloseHandle(hToken);
	CloseHandle(hTokenParent);

	return nExitCode;
}

PSID GetUserSidFromToken(HANDLE hToken)
{
	DWORD       dwLength;
	PTOKEN_USER pTokenUser;

	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
	pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);

	dwLength = GetLengthSid(pTokenUser->User.Sid);
	PSID pSid = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	CopySid(dwLength, pSid, pTokenUser->User.Sid);

	LocalFree(pTokenUser);

	return pSid;
}

DWORD GetParentProcessId()
{
	HANDLE         hSnapshot;
	DWORD          dwProcessId, dwParentProcessId;
	PROCESSENTRY32 pe;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	dwProcessId = GetCurrentProcessId();
	dwParentProcessId = -1;
	do {
		if (dwProcessId == pe.th32ProcessID) {
			dwParentProcessId = pe.th32ParentProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	return dwParentProcessId;
}
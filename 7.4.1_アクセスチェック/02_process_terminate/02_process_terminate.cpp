#include <windows.h>
#include <stdio.h>

DWORD WINAPI ThreadProc(LPVOID lpParameter);
DWORD GetProcessIdFromWindowClass(LPCWSTR lpszClassName);

// 他プロセスを強制終了させれることを確認

int main()
{
	ShellExecute(NULL, L"open", L"mspaint", NULL, NULL, SW_SHOWNORMAL);

	DWORD  dwProcessId = GetProcessIdFromWindowClass(L"MsPaintApp");
	DWORD  dwAccessMask = PROCESS_ALL_ACCESS;// dwAccessMask = SYNCHRONIZE;
	HANDLE hProcess = OpenProcess(dwAccessMask, FALSE, dwProcessId);
	if (hProcess == NULL) {
		printf("MsPaintAppのオープンに失敗");
		return -1;
	}

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc, hProcess, 0, NULL);

	int nExitCode = -1;
	DWORD dwResult;
	dwResult = WaitForSingleObject(hProcess, 2000);
	if (dwResult == WAIT_OBJECT_0) {
		printf("プロセスは終了した");
		nExitCode = 0;
	}
	else if (dwResult == WAIT_TIMEOUT)
		;
	else
		printf("エラー %d", dwResult);

	return nExitCode;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	HANDLE hProcess = lpParameter;

	TerminateProcess(hProcess, 0);
	if (GetLastError() == ERROR_ACCESS_DENIED)
		printf("アクセスが拒否された");

	return 0;
}

DWORD GetProcessIdFromWindowClass(LPCWSTR lpszClassName)
{
	HWND hwnd;
	int i = 0;
	for (i = 0; i < 10; i++) {
		hwnd = FindWindow(lpszClassName, NULL);
		if (hwnd != NULL)
			break;
		Sleep(100);
	}

	DWORD dwProcessId;
	GetWindowThreadProcessId(hwnd, &dwProcessId);

	return dwProcessId;
}

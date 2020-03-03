#include <stdio.h>
#include <windows.h>

int g_nExitCode = -1;

int Message_Send(LPWSTR lpszClassName);
HWND InitInstance(LPWSTR lpszClassName);
LRESULT CALLBACK CustomControlProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
HANDLE RestartProcess(LPWSTR lpszKey);
HANDLE GetNormalUserToken();

// 整合性レベルが低いプロセスから高いプロセスにウインドウメッセージを送信できることを確認

int main()
{
	WCHAR szKey[] = L"restart-key";
	WCHAR szClassName[] = L"my_app";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return Message_Send(szClassName);
	}

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("プロセス作成のため管理者として実行してください。");
		return -1;
	}

	HWND hwnd = InitInstance(szClassName);
	if (hwnd == NULL) {
		printf("ウインドウのセットアップに失敗");
		return -1;
	}

	RestartProcess(szKey);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	if (g_nExitCode == 0)
		printf("整合レベルが低いプロセスからメッセージを受信");
	else
		printf("整合レベルが低いプロセスからメッセージを受信できなかった");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return g_nExitCode;
}

int Message_Send(LPWSTR lpszClassName)
{
	HWND hwnd = FindWindow(lpszClassName, NULL);
	if (hwnd != NULL) {
		SendMessage(hwnd, WM_CLOSE, 0, 0);
		SendMessage(hwnd, WM_APP, 0, 0);
	}

	return 0;
}

HWND InitInstance(LPWSTR lpszClassName)
{
	HWND       hwnd;
	WNDCLASSEX wc;

	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = CustomControlProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = NULL;
	wc.hIcon = NULL;
	wc.hCursor = NULL;
	wc.hbrBackground = NULL;
	wc.lpszMenuName = NULL;
	wc.lpszClassName = lpszClassName;
	wc.hIconSm = NULL;

	if (RegisterClassEx(&wc) == 0)
		return NULL;

	hwnd = CreateWindowEx(0, lpszClassName, NULL, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, HWND_MESSAGE, NULL, NULL, NULL);
	if (hwnd == NULL)
		return NULL;

	return hwnd;
}

LRESULT CALLBACK CustomControlProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg) {

	case WM_CREATE:
		ChangeWindowMessageFilterEx(hwnd, WM_APP, MSGFLT_ALLOW, NULL);
		return 0;

	case WM_APP:
		g_nExitCode = 0;
		PostMessage(hwnd, WM_CLOSE, 0, 0);
		return 0;

	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;

	default:
		break;

	}

	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

HANDLE RestartProcess(LPWSTR lpszKey)
{
	HANDLE              hTokenMedium;
	WCHAR               szModuleName[MAX_PATH];
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	hTokenMedium = GetNormalUserToken();

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";
	if (CreateProcessWithTokenW(hTokenMedium, 0, szModuleName, lpszKey, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInformation)) {
		CloseHandle(processInformation.hThread);
	}
	else {
		processInformation.hProcess = NULL;
	}

	CloseHandle(hTokenMedium);

	return processInformation.hProcess;
}

HANDLE GetNormalUserToken()
{
	DWORD  dwProcessId;
	HANDLE hProcess;
	HANDLE hTokenNormal, hTokenDuplicate;

	GetWindowThreadProcessId(GetShellWindow(), &dwProcessId);
	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwProcessId);
	if (hProcess == NULL)
		return NULL;

	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hTokenNormal)) {
		CloseHandle(hProcess);
		return NULL;
	}

	DuplicateTokenEx(hTokenNormal, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &hTokenDuplicate);

	CloseHandle(hProcess);
	CloseHandle(hTokenNormal);

	return hTokenDuplicate;
}
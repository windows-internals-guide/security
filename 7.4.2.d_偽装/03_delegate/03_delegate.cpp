#include <windows.h>
#include <strsafe.h>

struct CServer {
	CServer();
	~CServer();
	void Handshake();
	HANDLE GetClientToken();

private:
	HANDLE InitNamedPipe();
	void WaitServer(HANDLE hPipe);
	HANDLE StartImpersonation(HANDLE hPipe);
	void ReadMsg(HANDLE hPipe, WCHAR szMessage1[], DWORD dwMessage1Size, WCHAR szMessage2[], DWORD dwMessage2Size);
	PSECURITY_DESCRIPTOR CreateSecurityDescriptor();

	HANDLE m_hTokenClient;
};

struct CClient {
	void Handshake();
private:
	HANDLE ConnectServer();
	void SendMsg(HANDLE hPipe);
	HANDLE GetFilterdAdminToken();
	DWORD GetProcessIdFromFileName(LPCWSTR lpszFileName);
};

// #define CLIENT_ONLY
// #define SERVER_ONLY
#define SERVER_CLIENT

DWORD WINAPI ThreadProc(LPVOID lpParameter);
HANDLE RestartProcess(LPWSTR lpszKey, HANDLE hToken);
BOOL CheckProcessAccount();
BOOL CheckAdmin();

// 偽装を通じてクライアントのトークンを取得し、それをベースにプロセスを起動できることを確認

int main()
{
#ifdef CLIENT_ONLY
	CClient client;
	client.Handshake();
	return 0;
#else
	WCHAR szKey[] = L"restart-key";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckProcessAccount();
	}

	if (!CheckAdmin()) {
		printf("プロセス作成のため管理者として実行してください。");
		return -1;
	}

	CServer server;

#ifdef SERVER_CLIENT
	CClient client;
	HANDLE  hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc, &client, 0, NULL);
#endif

	server.Handshake();

#ifdef SERVER_CLIENT
	CloseHandle(hThread);
#endif

	int nExitCode = -1;
	HANDLE hRestartProcess = RestartProcess(szKey, server.GetClientToken());
	if (hRestartProcess != NULL) {
		DWORD dwResult;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwResult);
		if (dwResult == 0) {
			printf("昇格していないクライアントプロセスを作成した。");
			nExitCode = 0;
		}
		else
			printf("作成したクライアントプロセスは昇格してしまっている。");
		CloseHandle(hRestartProcess);
	}
	else
		printf("クライアントプロセスの作成に失敗。 %d", GetLastError());

#ifdef _DEBUG
	geWCHAR();
#endif

	return nExitCode;
#endif
}

BOOL CheckProcessAccount()
{
	HANDLE hToken;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	DWORD           dwLength;
	TOKEN_ELEVATION tokenElevation;
	GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(TOKEN_ELEVATION), &dwLength);

	CloseHandle(hToken);

	return tokenElevation.TokenIsElevated == 0 ? 0 : -1;
}

HANDLE RestartProcess(LPWSTR lpszKey, HANDLE hToken)
{
	WCHAR               szModuleName[MAX_PATH];
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";
	if (CreateProcessWithTokenW(hToken, 0, szModuleName, lpszKey, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInformation)) {
		CloseHandle(processInformation.hThread);
	}
	else {
		processInformation.hProcess = NULL;
	}

	return processInformation.hProcess;
}

BOOL CheckAdmin()
{
	HANDLE          hToken;
	DWORD           dwLength;
	TOKEN_ELEVATION tokenElevation;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(TOKEN_ELEVATION), &dwLength);
	CloseHandle(hToken);

	return tokenElevation.TokenIsElevated;
}


// CServer


CServer::CServer()
{
	m_hTokenClient = NULL;
}

CServer::~CServer()
{
	if (m_hTokenClient != NULL)
		CloseHandle(m_hTokenClient);
}

HANDLE CServer::GetClientToken()
{
	return m_hTokenClient;
}

void CServer::Handshake()
{
	HANDLE hPipe = InitNamedPipe();

	if (hPipe == NULL)
		return;

	WaitServer(hPipe);

	WCHAR szMessage1[256], szMessage2[256];
	ReadMsg(hPipe, szMessage1, sizeof(szMessage1), szMessage2, sizeof(szMessage2));

	HANDLE hToken = StartImpersonation(hPipe);
	if (hToken != NULL) {
		if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &m_hTokenClient)) {
			printf("代理可能なプライマリトークンへの変換に失敗。 %d\n", GetLastError());
		}

		DWORD           dwLength;
		TOKEN_ELEVATION tokenElevation;
		GetTokenInformation(m_hTokenClient, TokenElevation, &tokenElevation, sizeof(TOKEN_ELEVATION), &dwLength);
		if (tokenElevation.TokenIsElevated)
			printf("クライアントが標準ユーザーなのにトークンが昇格してしまっている。\n");

		CloseHandle(hToken);
		RevertToSelf();
	}

	CloseHandle(hPipe);
}

HANDLE CServer::InitNamedPipe()
{
	HANDLE              hPipe;
	WCHAR               szData[256];
	SECURITY_ATTRIBUTES securityAttributes;

	securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	securityAttributes.lpSecurityDescriptor = CreateSecurityDescriptor();
	securityAttributes.bInheritHandle = FALSE;

	hPipe = CreateNamedPipe(L"\\\\.\\pipe\\SamplePipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, sizeof(szData), sizeof(szData), 1000, &securityAttributes);
	if (hPipe == INVALID_HANDLE_VALUE) {
		printf("名前付きパイプの作成に失敗。 %d", GetLastError());
		return NULL;
	}

	return hPipe;
}

void CServer::WaitServer(HANDLE hPipe)
{
	ConnectNamedPipe(hPipe, NULL);
}

HANDLE CServer::StartImpersonation(HANDLE hPipe)
{
	HANDLE hToken = NULL; // NULLで初期化

	if (!ImpersonateNamedPipeClient(hPipe)) {
		return NULL;
	}

	OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken);
	if (hToken == NULL) {
		printf("スレッドにトークンが割り当てられていない。プロセスにSE_IMPERSONATE_NAME特権が割り当てられていなかった可能性がある。\n");
		return NULL;
	}

	return hToken;
}

void CServer::ReadMsg(HANDLE hPipe, WCHAR szMessage1[], DWORD dwMessage1Size, WCHAR szMessage2[], DWORD dwMessage2Size)
{
	DWORD dwResult;

	ReadFile(hPipe, szMessage1, dwMessage1Size, &dwResult, NULL);
	ReadFile(hPipe, szMessage2, dwMessage2Size, &dwResult, NULL);
}

PSECURITY_DESCRIPTOR CServer::CreateSecurityDescriptor()
{
	SECURITY_DESCRIPTOR securityDescriptor;
	BYTE                dacl[1024];
	PACL                pDacl = (PACL)dacl;
	BYTE                sid[SECURITY_MAX_SID_SIZE];
	PSID                pSid = (PSID)sid;
	DWORD               dwSidSize = SECURITY_MAX_SID_SIZE;

	InitializeSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);

	CreateWellKnownSid(WinWorldSid, NULL, pSid, &dwSidSize);

	InitializeAcl(pDacl, 1024, ACL_REVISION);
	AddAccessAllowedAce(pDacl, ACL_REVISION, GENERIC_ALL, pSid);
	SetSecurityDescriptorDacl(&securityDescriptor, TRUE, pDacl, FALSE);

	DWORD                dwSDSize = 0;
	PSECURITY_DESCRIPTOR pSD;

	MakeSelfRelativeSD(&securityDescriptor, NULL, &dwSDSize);
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSDSize);
	MakeSelfRelativeSD(&securityDescriptor, pSD, &dwSDSize);

	return pSD;
}


// CClient


DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	CClient* lpClient = (CClient*)lpParameter;

	Sleep(1000);

	lpClient->Handshake();

	return 0;
}

void CClient::Handshake()
{
	HANDLE hPipe;
	HANDLE hToken = GetFilterdAdminToken();

	ImpersonateLoggedOnUser(hToken);
	hPipe = ConnectServer();
	RevertToSelf();

	SendMsg(hPipe);

	CloseHandle(hPipe);
	CloseHandle(hToken);
}

HANDLE CClient::ConnectServer()
{
	WCHAR  szRemoteName[] = L"localhost";
	DWORD  dwImpersonationLevel = SECURITY_IMPERSONATION;
	WCHAR  szPipeName[256];
	HANDLE hPipe;

	StringCchPrintf(szPipeName, ARRAYSIZE(szPipeName), L"\\\\%s\\pipe\\SamplePipe", szRemoteName);
	hPipe = CreateFile(szPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | dwImpersonationLevel, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) {
		printf("名前付きパイプの接続に失敗した。 %d", GetLastError());
		return NULL;
	}

	return hPipe;
}

void CClient::SendMsg(HANDLE hPipe)
{
	WCHAR  szMessage1[] = L"Message1";
	WCHAR  szMessage2[] = L"Message2";
	DWORD  dwResult;

	WriteFile(hPipe, szMessage1, sizeof(szMessage1), &dwResult, NULL);
	WriteFile(hPipe, szMessage2, sizeof(szMessage2), &dwResult, NULL);
}

HANDLE CClient::GetFilterdAdminToken()
{
	HANDLE  hProcess;
	HANDLE  hTokenNormal, hTokenDuplicate;

	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, GetProcessIdFromFileName(L"explorer.exe"));
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

#include <tlhelp32.h>
DWORD CClient::GetProcessIdFromFileName(LPCWSTR lpszFileName)
{
	HANDLE         hSnapshot;
	DWORD          dwProcessId;
	PROCESSENTRY32 pe;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	dwProcessId = -1;
	do {
		if (lstrcmp(pe.szExeFile, lpszFileName) == 0) {
			dwProcessId = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	return dwProcessId;
}

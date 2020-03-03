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
	void ReadMsg(HANDLE hPipe, WCHAR szUserName[], DWORD dwUserNameSize, WCHAR szPasswordName[], DWORD dwPasswordNameSize);
	PSECURITY_DESCRIPTOR CreateSecurityDescriptor();

	HANDLE m_hTokenClient;
};

struct CClient {
	void Handshake();
private:
	HANDLE ConnectServer();
	void SendMsg(HANDLE hPipe);
};

// #define CLIENT_ONLY
// #define SERVER_ONLY
#define SERVER_CLIENT

DWORD WINAPI ThreadProc(LPVOID lpParameter);
HANDLE RestartProcess(LPWSTR lpszKey, HANDLE hToken);
BOOL CheckProcessAccount();
BOOL CheckAdmin();

// クライアントから資格情報を受け取ってログオンさせ、それをベースにプロセスを起動できることを確認

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
		if (dwResult == ERROR_DLL_INIT_FAILED) {
			printf("作成したクライアントプロセスがウインドウステーション/デスクトップにアクセスできない事を確認。");
			nExitCode = 0;
		}
		else
			printf("クライアントプロセスは正しくない。 %d", dwResult);
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
	HINSTANCE hmod = LoadLibrary(L"user32.dll");

	if (hmod != NULL)
		FreeLibrary(hmod);

	return GetLastError();
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

	WCHAR szUserName[256], szPassword[256];
	ReadMsg(hPipe, szUserName, sizeof(szUserName), szPassword, sizeof(szPassword));

	if (!LogonUser(szUserName, NULL, szPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &m_hTokenClient)) {
		printf("ログオンに失敗。 %d", GetLastError());
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

void CServer::ReadMsg(HANDLE hPipe, WCHAR szUserName[], DWORD dwUserNameSize, WCHAR szPasswordName[], DWORD dwPasswordNameSize)
{
	DWORD dwResult;

	ReadFile(hPipe, szUserName, dwUserNameSize, &dwResult, NULL);
	ReadFile(hPipe, szPasswordName, dwPasswordNameSize, &dwResult, NULL);
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

	hPipe = ConnectServer();

	SendMsg(hPipe);

	CloseHandle(hPipe);
}

HANDLE CClient::ConnectServer()
{
	WCHAR  szRemoteName[] = L"localhost";
	DWORD  dwImpersonationLevel = SECURITY_IDENTIFICATION;
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
	WCHAR  szUserName[] = L"kens";
	WCHAR  szPassword[] = L"luna";
	DWORD  dwResult;

	WriteFile(hPipe, szUserName, sizeof(szUserName), &dwResult, NULL);
	WriteFile(hPipe, szPassword, sizeof(szPassword), &dwResult, NULL);
}
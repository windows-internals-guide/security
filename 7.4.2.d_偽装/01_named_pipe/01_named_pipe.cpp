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

	HANDLE m_hTokenClient;
};

struct CClient {
	void Handshake();
private:
	HANDLE ConnectServer();
	void WriteMsg(HANDLE hPipe);
};

// #define CLIENT_ONLY
// #define SERVER_ONLY
#define SERVER_CLIENT

DWORD WINAPI ThreadProc(LPVOID lpParameter);

// サーバーがクライアントを偽装できるか確認

int main()
{
#ifdef CLIENT_ONLY
	CClient client;
	client.Handshake();
	return 0;
#else

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
	if (server.GetClientToken() != NULL) {
		printf("クライアントを偽装できた。");
		nExitCode = 0;
	}
	else
		printf("クライアントを偽装できなかった。");

	return nExitCode;
#endif
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
		RevertToSelf();
		m_hTokenClient = hToken;
	}

	CloseHandle(hPipe);
}

HANDLE CServer::InitNamedPipe()
{
	HANDLE hPipe;
	WCHAR  szData[256];

	hPipe = CreateNamedPipe(L"\\\\.\\pipe\\SamplePipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, sizeof(szData), sizeof(szData), 1000, NULL);
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

	WriteMsg(hPipe);

	CloseHandle(hPipe);
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

void CClient::WriteMsg(HANDLE hPipe)
{
	WCHAR  szMessage1[] = L"Message1";
	WCHAR  szMessage2[] = L"Message2";
	DWORD  dwResult;

	WriteFile(hPipe, szMessage1, sizeof(szMessage1), &dwResult, NULL);
	WriteFile(hPipe, szMessage2, sizeof(szMessage2), &dwResult, NULL);
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ws2tcpip.h>
#include <strsafe.h>
#include <userenv.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "userenv.lib")

class CAppContainer {
public:
	CAppContainer();
	~CAppContainer();
	HRESULT Create();
	HANDLE RunAsAppContainerProcess(LPWSTR lpszKey);
	void SetCapabilitySid(PSID pSidArray[], DWORD dwSidCount);
	void SetCapabilityWellKnownSid(WELL_KNOWN_SID_TYPE sidTypeArray[], DWORD dwSidCount);
	void FreeCapabilitySid();
	PSID GetAppContainerSid();
	void EnableHandleInheritance();

private:
	PSID  m_pSidAppContainer;
	WCHAR m_szContainerName[256];
	PSID_AND_ATTRIBUTES m_pSidAttributes;
	DWORD m_dwSidCount;
	BOOL m_bHandleInheritance;
};

int CheckAppContainerState();

// InternetClientケーパビリティを指定することで、ネットワーク通信ができることの確認

int main()
{
	WCHAR szKey[] = L"restart-key";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckAppContainerState();
	}

	CAppContainer appContainer;

	HRESULT hr = appContainer.Create();
	if (FAILED(hr)) {
		printf("アプリコンテナーの作成に失敗 %08x", hr);
		return -1;
	}

	WELL_KNOWN_SID_TYPE sidTypeArray[] = { WinCapabilityInternetClientSid };
	appContainer.SetCapabilityWellKnownSid(sidTypeArray, ARRAYSIZE(sidTypeArray));

	int    nExitCode = -1;
	HANDLE hRestartProcess = appContainer.RunAsAppContainerProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwExitCode;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwExitCode);
		if (dwExitCode == 0) {
			printf("InternetClientケーパビリティが存在することでネットワーク通信できた");
			nExitCode = 0;
		}
		else
			printf("InternetClientケーパビリティを指定したのにネットワーク通信できなかった");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

int CheckAppContainerState()
{
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return -1;
	}

	ADDRINFOW  hints = { 0 };
	PADDRINFOW pAddrInfo;
	int        nResult;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	nResult = GetAddrInfoW(L"docs.microsoft.com", NULL, &hints, &pAddrInfo);
	if (nResult != NO_ERROR) { // WSAHOST_NOT_FOUND
		WCHAR szIPAddress[256];
		DWORD dwSize = ARRAYSIZE(szIPAddress);
		WSAAddressToString(pAddrInfo->ai_addr, pAddrInfo->ai_addrlen, NULL, szIPAddress, &dwSize);
		FreeAddrInfo(pAddrInfo);
	}

	WSACleanup();

	return nResult == NO_ERROR ? 0 : -1;
}


// CAppContainer


CAppContainer::CAppContainer()
{
	m_pSidAppContainer = NULL;
	m_szContainerName[0] = '\0';
	m_pSidAttributes = NULL;
	m_dwSidCount = 0;
}

CAppContainer::~CAppContainer()
{
	if (m_szContainerName[0] != '\0')
		DeleteAppContainerProfile(m_szContainerName);

	if (m_pSidAppContainer != NULL)
		FreeSid(m_pSidAppContainer);
}

HRESULT CAppContainer::Create()
{
	HRESULT hr;

	StringCchCopy(m_szContainerName, ARRAYSIZE(m_szContainerName), L"ContainerName");

	hr = CreateAppContainerProfile(m_szContainerName, L"DisplayName", L"Description", 0, 0, &m_pSidAppContainer);
	if (FAILED(hr)) {
		if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
			hr = DeriveAppContainerSidFromAppContainerName(m_szContainerName, &m_pSidAppContainer);
		}
	}

	return hr;
}

HANDLE CAppContainer::RunAsAppContainerProcess(LPWSTR lpszKey)
{
	if (m_pSidAppContainer == NULL)
		return NULL;

	SECURITY_CAPABILITIES securityCapabilities;
	securityCapabilities.AppContainerSid = m_pSidAppContainer;
	securityCapabilities.Reserved = NULL;
	securityCapabilities.Capabilities = m_pSidAttributes;
	securityCapabilities.CapabilityCount = m_dwSidCount;

	STARTUPINFOEX startupInfoEx = { 0 };
	SIZE_T        size;
	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	startupInfoEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)LocalAlloc(LPTR, size);
	InitializeProcThreadAttributeList(startupInfoEx.lpAttributeList, 1, 0, &size);
	UpdateProcThreadAttribute(startupInfoEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &securityCapabilities, sizeof(securityCapabilities), NULL, NULL);

	WCHAR               szModuleName[MAX_PATH];
	PROCESS_INFORMATION processInformation;
	GetModuleFileName(NULL, szModuleName, MAX_PATH);
	startupInfoEx.StartupInfo.cb = sizeof(startupInfoEx);
	if (CreateProcess(szModuleName, lpszKey, NULL, NULL, m_bHandleInheritance, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)& startupInfoEx, &processInformation)) {
		CloseHandle(processInformation.hThread);
	}
	else {
		processInformation.hProcess = NULL;
	}

	if (startupInfoEx.lpAttributeList != NULL) {
		DeleteProcThreadAttributeList(startupInfoEx.lpAttributeList);
		LocalFree(startupInfoEx.lpAttributeList);
	}

	FreeCapabilitySid();

	return processInformation.hProcess;
}

void CAppContainer::SetCapabilitySid(PSID pSidArray[], DWORD dwSidCount)
{
	DWORD i;

	m_pSidAttributes = (PSID_AND_ATTRIBUTES)LocalAlloc(LPTR, sizeof(SID_AND_ATTRIBUTES) * dwSidCount);
	m_dwSidCount = dwSidCount;

	for (i = 0; i < dwSidCount; i++) {
		m_pSidAttributes[i].Sid = pSidArray[i];
		m_pSidAttributes[i].Attributes = SE_GROUP_ENABLED;
	}
}

void CAppContainer::SetCapabilityWellKnownSid(WELL_KNOWN_SID_TYPE sidTypeArray[], DWORD dwSidCount)
{
	DWORD i, dwSidSize;

	m_pSidAttributes = (PSID_AND_ATTRIBUTES)LocalAlloc(LPTR, sizeof(SID_AND_ATTRIBUTES) * dwSidCount);
	m_dwSidCount = dwSidCount;

	for (i = 0; i < dwSidCount; i++) {
		CreateWellKnownSid(sidTypeArray[i], NULL, NULL, &dwSidSize);
		m_pSidAttributes[i].Sid = LocalAlloc(LPTR, dwSidSize);
		CreateWellKnownSid(sidTypeArray[i], NULL, m_pSidAttributes[i].Sid, &dwSidSize);

		m_pSidAttributes[i].Attributes = SE_GROUP_ENABLED;
	}
}

void CAppContainer::FreeCapabilitySid()
{
	if (m_pSidAttributes == NULL)
		return;

	DWORD i;

	for (i = 0; i < m_dwSidCount; i++) {
		LocalFree(m_pSidAttributes[i].Sid);
	}

	if (m_pSidAttributes != NULL)
		LocalFree(m_pSidAttributes);
}

PSID CAppContainer::GetAppContainerSid()
{
	return m_pSidAppContainer;
}

void CAppContainer::EnableHandleInheritance()
{
	m_bHandleInheritance = TRUE;
}

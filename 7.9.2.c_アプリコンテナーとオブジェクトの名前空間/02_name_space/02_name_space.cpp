#include <windows.h>
#include <strsafe.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlwapi.h>

#pragma comment(lib, "userenv.lib")
#pragma comment (lib, "shlwapi.lib")

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

#define EVENT_NORMAL 0x01
#define EVENT_GLOBAL 0x02
#define EVENT_SECURITY 0x04
#define EVENT_NONAME 0x08

#define HANDLE_FILE L"handle.txt"

void SetupEventObject(HANDLE hEventArray[], int nCount, PSID pSidAppContainer);
PSECURITY_DESCRIPTOR CreateSecurityDescriptor();
PSID GetLogonSid();
BOOL WriteEventObjectHandle(PSID pSidAppContainer, DWORD dwAddress);

int CheckAppContainerState();
BOOL ReadEventObjectHandle(PSID pSidAppContainer, LPDWORD lpdwAddress);
PSID GetAppContainerSid();

// デスクトップアプリが作成した特定のイベントに関しては、アプリコンテナー環境下でもアクセスできることを確認

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

	HANDLE hEventArray[4] = { 0 };
	SetupEventObject(hEventArray, ARRAYSIZE(hEventArray), appContainer.GetAppContainerSid());

	appContainer.EnableHandleInheritance();

	int    nExitCode = -1;
	HANDLE hRestartProcess = appContainer.RunAsAppContainerProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwExitCode;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwExitCode);
		if (dwExitCode == (EVENT_SECURITY | EVENT_NONAME)) {
			HANDLE hHandles[] = { hEventArray[2], hEventArray[3] };
			DWORD dwResult = WaitForMultipleObjects(2, hHandles, TRUE, 500);
			if (dwResult == WAIT_OBJECT_0) {
				printf("一部イベントオブジェクトにアクセスできた");
				nExitCode = 0;
			}
			else
				printf("SetEventが機能していない");
		}
		else
			printf("ハンドル取得の結果が想定外 %d", dwExitCode);

		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗");
	
#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

void SetupEventObject(HANDLE hEventArray[], int nCount, PSID pSidAppContainer)
{
	hEventArray[0] = CreateEvent(NULL, TRUE, FALSE, L"MyEvent");

	hEventArray[1] = CreateEvent(NULL, TRUE, FALSE, L"Global\\MyEventGlobal");

	SECURITY_ATTRIBUTES securityAttributes;
	securityAttributes.nLength = sizeof(securityAttributes);
	securityAttributes.bInheritHandle = FALSE;
	securityAttributes.lpSecurityDescriptor = CreateSecurityDescriptor();
	hEventArray[2] = CreateEvent(&securityAttributes, TRUE, FALSE, L"MyEventSecurity");
	LocalFree(securityAttributes.lpSecurityDescriptor);

	securityAttributes.nLength = sizeof(securityAttributes);
	securityAttributes.bInheritHandle = TRUE;
	securityAttributes.lpSecurityDescriptor = NULL;
	hEventArray[3] = CreateEvent(&securityAttributes, TRUE, FALSE, L"");
	WriteEventObjectHandle(pSidAppContainer, (DWORD)hEventArray[3]);
}

PSECURITY_DESCRIPTOR CreateSecurityDescriptor()
{
	int             i;
	int             nAceCount = 2;
	PSID            pSid[2];
	DWORD           dwAccessMask[] = { GENERIC_ALL, GENERIC_ALL };
	EXPLICIT_ACCESS explicitAccess[2] = { 0 };

	pSid[0] = GetLogonSid();

	// ALL APPLICATION PACKAGESの代わりにpSidAppContainerは使えない
	SID_IDENTIFIER_AUTHORITY sidAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
	AllocateAndInitializeSid(&sidAuthority, SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT, SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE,
		0, 0, 0, 0, 0, 0, &pSid[1]);

	for (i = 0; i < nAceCount; i++) {
		explicitAccess[i].grfAccessPermissions = dwAccessMask[i];
		explicitAccess[i].grfAccessMode = SET_ACCESS;
		explicitAccess[i].grfInheritance = NO_INHERITANCE;
		explicitAccess[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		explicitAccess[i].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		explicitAccess[i].Trustee.ptstrName = (LPWSTR)pSid[i];
	}

	PACL pDacl;
	SetEntriesInAcl(nAceCount, explicitAccess, NULL, &pDacl);

	PSECURITY_DESCRIPTOR pSecurityDescriptor = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	InitializeSecurityDescriptor(pSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(pSecurityDescriptor, TRUE, pDacl, FALSE);

	LocalFree(pDacl);
	FreeSid(pSid[0]);
	FreeSid(pSid[1]);

	return pSecurityDescriptor;
}

PSID GetLogonSid()
{
	DWORD         dwLength;
	PTOKEN_GROUPS pTokenGroups;
	HANDLE        hToken;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenLogonSid, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenLogonSid, pTokenGroups, dwLength, &dwLength);
	CloseHandle(hToken);

	dwLength = GetLengthSid(pTokenGroups->Groups[0].Sid);
	PSID pSid = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	CopySid(dwLength, pSid, pTokenGroups->Groups[0].Sid);

	return pSid;
}

BOOL WriteEventObjectHandle(PSID pSidAppContainer, DWORD dwAddress)
{
	LPWSTR lpszSid;
	LPWSTR lpszAppContainerFolderPath;
	WCHAR  szFilePath[256];

	ConvertSidToStringSid(pSidAppContainer, &lpszSid);
	GetAppContainerFolderPath(lpszSid, &lpszAppContainerFolderPath);
	StringCchPrintf(szFilePath, ARRAYSIZE(szFilePath), L"%s\\%s", lpszAppContainerFolderPath, HANDLE_FILE);
	CoTaskMemFree(lpszAppContainerFolderPath);
	LocalFree(lpszSid);

	HANDLE hFile = CreateFile(szFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD dwWriteByte;
	WCHAR szData[256];
	StringCchPrintf(szData, ARRAYSIZE(szData), L"%d", dwAddress);
	WriteFile(hFile, szData, (lstrlen(szData) + 1) * sizeof(WCHAR), &dwWriteByte, NULL);
	CloseHandle(hFile);

	return TRUE;
}

int CheckAppContainerState()
{
	HANDLE hEvent;
	DWORD  dwFlags = 0;

	hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"MyEvent");
	if (hEvent != NULL) {
		dwFlags |= EVENT_NORMAL;
		CloseHandle(hEvent);
	}

	hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"Global\\MyEventGlobal");
	if (hEvent != NULL) {
		dwFlags |= EVENT_GLOBAL;
		CloseHandle(hEvent);
	}

	hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"MyEventSecurity");
	if (hEvent != NULL) {
		dwFlags |= EVENT_SECURITY;
		SetEvent(hEvent);
		CloseHandle(hEvent);
	}

	DWORD dwAddress;
	PSID pAppContainerSid = GetAppContainerSid();
	ReadEventObjectHandle(pAppContainerSid, &dwAddress);
	FreeSid(pAppContainerSid);

	hEvent = (HANDLE)dwAddress;

	DWORD dwInfo;
	GetHandleInformation(hEvent, &dwInfo);
	if (dwInfo == HANDLE_FLAG_INHERIT) {
		dwFlags |= EVENT_NONAME;
		SetEvent(hEvent);
	}

	return dwFlags;
}

BOOL ReadEventObjectHandle(PSID pSidAppContainer, LPDWORD lpdwAddress)
{
	LPWSTR lpszSid;
	LPWSTR lpszAppContainerFolderPath;
	WCHAR  szFilePath[MAX_PATH];

	ConvertSidToStringSid(pSidAppContainer, &lpszSid);
	GetAppContainerFolderPath(lpszSid, &lpszAppContainerFolderPath);
	StringCchPrintf(szFilePath, ARRAYSIZE(szFilePath), L"%s\\%s", lpszAppContainerFolderPath, HANDLE_FILE);
	CoTaskMemFree(lpszAppContainerFolderPath);
	LocalFree(lpszSid);

	HANDLE hFile = CreateFile(szFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD  dwFileSize = GetFileSize(hFile, NULL);
	LPWSTR lpszFileText = (LPWSTR)LocalAlloc(LPTR, dwFileSize);
	DWORD  dwReadByte;
	ReadFile(hFile, lpszFileText, dwFileSize, &dwReadByte, NULL);
	CloseHandle(hFile);

	*lpdwAddress = (DWORD)StrToInt(lpszFileText);
	LocalFree(lpszFileText);

	return TRUE;
}

PSID GetAppContainerSid()
{
	DWORD                           dwLength;
	PTOKEN_APPCONTAINER_INFORMATION pAppConteiner;
	HANDLE                          hToken;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenAppContainerSid, NULL, 0, &dwLength);
	pAppConteiner = (PTOKEN_APPCONTAINER_INFORMATION)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenAppContainerSid, pAppConteiner, dwLength, &dwLength);
	CloseHandle(hToken);

	dwLength = GetLengthSid(pAppConteiner->TokenAppContainer);
	PSID pSid = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	CopySid(dwLength, pSid, pAppConteiner->TokenAppContainer);

	return pSid;
}


// CAppContainer


CAppContainer::CAppContainer()
{
	m_pSidAppContainer = NULL;
	m_szContainerName[0] = '\0';
	m_pSidAttributes = NULL;
	m_dwSidCount = 0;
	m_bHandleInheritance = FALSE;
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
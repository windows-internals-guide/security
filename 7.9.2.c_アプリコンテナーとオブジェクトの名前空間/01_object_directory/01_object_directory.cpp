#include <windows.h>
#include <strsafe.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>

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

BOOL CheckDesktopAppObject();
BOOL IsAppContainerNamedObjectCreated(PSID pSidAppContainer);
BOOL IsObjectDefined(LPCWSTR lpszName, LPCWSTR lpszDirectory);
int CheckAppContainerState();

// アプリコンテナープロセスがオブジェクトを作成した時、アプリコンテナーの名前空間に作成されているかを確認

int main()
{
	WCHAR szKey[] = L"restart-key";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckAppContainerState();
	}

	if (!CheckDesktopAppObject()) {
		printf("オブジェクトが適切に作成されない");
		return -1;
	}

	CAppContainer appContainer;

	HRESULT hr = appContainer.Create();
	if (FAILED(hr)) {
		printf("アプリコンテナーの作成に失敗 %08x", hr);
		return -1;
	}

	if (IsAppContainerNamedObjectCreated(appContainer.GetAppContainerSid())) {
		printf("アプリコンテナープロセスを起動していないのにディレクトリが作成されている");
		return -1;
	}

	int    nExitCode = -1;
	HANDLE hRestartProcess = appContainer.RunAsAppContainerProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwExitCode;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwExitCode);
		if (dwExitCode == 0) {
			printf("オブジェクトディレクトリにイベントオブジェクトを確認");
			nExitCode = 0;
		}
		else
			printf("オブジェクトディレクトリのイベントオブジェクトを確認できない");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗");
	
#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

BOOL CheckDesktopAppObject()
{
	DWORD dwSessionId;
	WCHAR szObjectDirectory[MAX_PATH];
	ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);
	StringCchPrintf(szObjectDirectory, ARRAYSIZE(szObjectDirectory), L"\\Sessions\\%d\\BaseNamedObjects", dwSessionId);

	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, L"MyEvent");
	BOOL bResult = IsObjectDefined(L"MyEvent", szObjectDirectory);
	CloseHandle(hEvent);
	if (!bResult)
		return FALSE;

	hEvent = CreateEvent(NULL, TRUE, FALSE, L"Global\\MyEvent");
	bResult = IsObjectDefined(L"MyEvent", L"\\BaseNamedObjects");
	CloseHandle(hEvent);
	if (!bResult)
		return FALSE;

	return TRUE;
}

BOOL IsAppContainerNamedObjectCreated(PSID pSidAppContainer)
{
	DWORD dwSessionId;
	ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);

	WCHAR szNamedObjectPath[MAX_PATH];
	ULONG uReturnPath;
	WCHAR szObjectDirectory[MAX_PATH];

	GetAppContainerNamedObjectPath(NULL, pSidAppContainer, MAX_PATH, szNamedObjectPath, &uReturnPath);
	StringCchPrintf(szObjectDirectory, ARRAYSIZE(szObjectDirectory), L"\\Sessions\\%d\\%s", dwSessionId, szNamedObjectPath);

	return IsObjectDefined(NULL, szObjectDirectory);
}

#include <winternl.h>
#pragma comment (lib, "ntdll.lib")

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002

typedef NTSTATUS(WINAPI * LPFNNTOPENDIRECTORYOBJECT)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(WINAPI* LPFNNTQUERYDIRECTORYOBJECT)(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length,
	BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);
LPFNNTOPENDIRECTORYOBJECT lpfnNtOpenDirectoryObject;
LPFNNTQUERYDIRECTORYOBJECT lpfnNtQueryDirectoryObject;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

BOOL IsObjectDefined(LPCWSTR lpszName, LPCWSTR lpszDirectory)
{
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");

	lpfnNtOpenDirectoryObject = (LPFNNTOPENDIRECTORYOBJECT)GetProcAddress(hModule, "NtOpenDirectoryObject");
	lpfnNtQueryDirectoryObject = (LPFNNTQUERYDIRECTORYOBJECT)GetProcAddress(hModule, "NtQueryDirectoryObject");
	if (lpfnNtOpenDirectoryObject == NULL || lpfnNtQueryDirectoryObject == NULL)
		return FALSE;

	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING    name;
	RtlInitUnicodeString(&name, lpszDirectory);
	InitializeObjectAttributes(&objectAttributes, &name, 0, NULL, NULL);

	HANDLE hDirectory;
	NTSTATUS ns = lpfnNtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &objectAttributes);
	if (!NT_SUCCESS(ns))
		return FALSE;

	if (lpszName == NULL) {
		NtClose(hDirectory);
		return TRUE;
	}

	ULONG uContext = 0;
	ULONG uLength;
	lpfnNtQueryDirectoryObject(hDirectory, NULL, 0, FALSE, TRUE, &uContext, &uLength);
	POBJECT_DIRECTORY_INFORMATION pInfo = (POBJECT_DIRECTORY_INFORMATION)LocalAlloc(LPTR, uLength);
	lpfnNtQueryDirectoryObject(hDirectory, pInfo, uLength, FALSE, TRUE, &uContext, &uLength);

	BOOL bResult = FALSE;
	for (ULONG i = 0; i < uContext; i++) {
		if (lstrcmp(pInfo[i].Name.Buffer, lpszName) == 0) {
			bResult = TRUE;
			break;
		}
	}

	LocalFree(pInfo);
	NtClose(hDirectory);

	return bResult;
}

int CheckAppContainerState()
{
	DWORD dwSessionId;
	ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);

	WCHAR szNamedObjectPath[MAX_PATH];
	ULONG uReturnPath;
	WCHAR szObjectDirectory[MAX_PATH];
	GetAppContainerNamedObjectPath(NULL, NULL, MAX_PATH, szNamedObjectPath, &uReturnPath);
	StringCchPrintf(szObjectDirectory, ARRAYSIZE(szObjectDirectory), L"\\Sessions\\%d\\%s", dwSessionId, szNamedObjectPath);

	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, L"MyEvent");
	BOOL bResult = IsObjectDefined(L"MyEvent", szObjectDirectory);
	CloseHandle(hEvent);
	if (!bResult)
		return -1;

	hEvent = CreateEvent(NULL, TRUE, FALSE, L"Global\\MyEvent");
	if (hEvent != NULL)
		return -1;

	return 0;
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

/*
// TokenBnoIsolation

#define ProcThreadAttributeBnoIsolation  19

#define PROC_THREAD_ATTRIBUTE_BNO_ISOLATION \
	ProcThreadAttributeValue (ProcThreadAttributeBnoIsolation, FALSE, TRUE, FALSE)
*/
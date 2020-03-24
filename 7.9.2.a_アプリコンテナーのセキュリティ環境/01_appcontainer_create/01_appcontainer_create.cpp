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

#define ATOM_NAME L"atom_name"

PSID GetAppConteinerSid();
int CheckAppContainerState();
BOOL CheckAppContainerFolderSecurity(LPWSTR lpszFilePath, PSID pSid);

// アプリコンテナープロセスのトークンからアプリコンテナーSIDを取得し、ディレクトリのセキュリティ記述子に含まれるか確認

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

	ATOM atom = GlobalAddAtom(ATOM_NAME);

	int    nExitCode = -1;
	HANDLE hRestartProcess = appContainer.RunAsAppContainerProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwExitCode;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwExitCode);
		if (dwExitCode == 0) {
			printf("アプリコンテナーSIDを確認。");
			nExitCode = 0;
		}
		else
			printf("アプリコンテナーSIDを確認できなかった。");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗。");

	GlobalDeleteAtom(atom);

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

int CheckAppContainerState()
{
	ATOM atom = GlobalFindAtom(ATOM_NAME);

	if (atom == 0)
		return -1;

	PSID pSidAppContainer = GetAppConteinerSid();
	LPWSTR lpszSid;
	ConvertSidToStringSid(pSidAppContainer, &lpszSid);

	LPWSTR lpszFolderPath;
	GetAppContainerFolderPath(lpszSid, &lpszFolderPath);

	BOOL bResult = CheckAppContainerFolderSecurity(lpszFolderPath, pSidAppContainer);

	CoTaskMemFree(lpszFolderPath);
	LocalFree(lpszSid);

	return bResult;
}

BOOL CheckAppContainerFolderSecurity(LPWSTR lpszFolderPath, PSID pSidAppContainer)
{
	BOOL                 bResult = FALSE;
	DWORD                i;
	PACL                 pDacl;
	PACCESS_ALLOWED_ACE  pAce;
	ACL_SIZE_INFORMATION aclInformation;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;

	if (GetNamedSecurityInfo(lpszFolderPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSecurityDescriptor) != ERROR_SUCCESS) {
		return FALSE;
	}

	GetAclInformation(pDacl, &aclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

	for (i = 0; i < aclInformation.AceCount; i++) {
		GetAce(pDacl, i, (LPVOID*)& pAce);
		PSID pSidAce = (PSID)& pAce->SidStart;
		if (EqualSid(pSidAce, pSidAppContainer)) {
			bResult = TRUE;
			break;
		}
	}

	LocalFree(pSecurityDescriptor);

	return bResult ? 0 : -1;
}

PSID GetAppConteinerSid()
{
	DWORD                           dwLength;
	PTOKEN_APPCONTAINER_INFORMATION pAppConteiner;
	HANDLE                          hToken;
	PSID                            pSid;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	GetTokenInformation(hToken, TokenAppContainerSid, NULL, 0, &dwLength);
	pAppConteiner = (PTOKEN_APPCONTAINER_INFORMATION)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenAppContainerSid, pAppConteiner, dwLength, &dwLength);
	if (pAppConteiner == NULL || pAppConteiner->TokenAppContainer == NULL) {
		return NULL;
	}

	dwLength = GetLengthSid(pAppConteiner->TokenAppContainer);
	pSid = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	CopySid(dwLength, pSid, pAppConteiner->TokenAppContainer);

	LocalFree(pAppConteiner);
	CloseHandle(hToken);

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

#if 0

#include <roapi.h>
#include <windows.storage.h>
using namespace ABI::Windows::Storage;
#pragma comment (lib, "RuntimeObject.lib")

BOOL CheckApplicationData()
{
	HRESULT hr;

	hr = RoInitialize(RO_INIT_MULTITHREADED);
	if (FAILED(hr)) {
		return FALSE;
	}

	HSTRING hString;
	LPCWSTR lpszSource = L"Windows.Storage.ApplicationData";

	hr = WindowsCreateString(lpszSource, lstrlen(lpszSource), &hString);
	if (hString == NULL || FAILED(hr)) {
		RoUninitialize();
		return FALSE;
	}

	IApplicationDataStatics* pApplicationDataStatics;

	hr = RoGetActivationFactory(hString, IID_PPV_ARGS(&pApplicationDataStatics));
	if (FAILED(hr)) {
		WindowsDeleteString(hString);
		RoUninitialize();
		return FALSE;
	}

	IApplicationData* pApplicationData;

	hr = pApplicationDataStatics->get_Current(&pApplicationData);
	if (pApplicationData == NULL) {
		// The process has no package identity.
		WindowsDeleteString(hString);
		RoUninitialize();
		return FALSE;
	}

	pApplicationData->Release();
	WindowsDeleteString(hString);
	RoUninitialize();

	return TRUE;
}

#endif
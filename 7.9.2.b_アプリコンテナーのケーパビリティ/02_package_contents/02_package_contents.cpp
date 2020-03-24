#include <windows.h>
#include <strsafe.h>
#include <userenv.h>
#include <aclapi.h>

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

PSID CreatePackageContentsSid();
LPBYTE CreateSHA2Hash(LPWSTR lpszName);
PSID GetPackageContentsSidFromWindowsApps();
BOOL IsCapabilitySid(PSID pSid);
int CheckAppContainerState();
void GetUWPFolderPathFromFileName(LPWSTR lpszFolderPath, BOOL bSubFolder, LPVOID lp);

// WindowsAppsに含まれるSIDをケーパビリティとして指定することで、WindowsAppsディレクトリへのアクセスが可能になることを確認

int main()
{
	WCHAR szKey[] = L"restart-key";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckAppContainerState();
	}

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("WindowsAppsアクセスのため管理者として実行してください。");
		return NULL;
	}

	PSID pSid;

#if 1
	pSid = CreatePackageContentsSid();
#else
	pSid = GetPackageContentsSidFromWindowsApps();
#endif

	if (pSid == NULL) {
		return -1;
	}

	CAppContainer appContainer;

	HRESULT hr = appContainer.Create();
	if (FAILED(hr)) {
		LocalFree(pSid);
		printf("アプリコンテナーの作成に失敗 %08x", hr);
		return -1;
	}

	appContainer.SetCapabilitySid(&pSid, 1);

	int    nExitCode = -1;
	HANDLE hRestartProcess = appContainer.RunAsAppContainerProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwExitCode;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwExitCode);
		if (dwExitCode == 0) {
			printf("WindowsApps内のファイルを開けた");
			nExitCode = 0;
		}
		else
			printf("WindowsApps内のファイルを開けなかった");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗");
	
#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

PSID CreatePackageContentsSid()
{
	LPCWSTR lpszCapabilityName = L"packageContents"; // wincap
	WCHAR   szName[256];

	StringCchCopy(szName, ARRAYSIZE(szName), lpszCapabilityName);
	CharUpper(szName);
	LPBYTE lpHashData = CreateSHA2Hash(szName);
	if (lpHashData == NULL)
		return NULL;

	SID_IDENTIFIER_AUTHORITY identifierAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
	PISID                    pSid = (PISID)LocalAlloc(LPTR, MAX_SID_SIZE);
	pSid->Revision = 1;
	pSid->SubAuthorityCount = 1 + 1 + 8;
	CopyMemory(&pSid->IdentifierAuthority, &identifierAuthority, sizeof(identifierAuthority));
	pSid->SubAuthority[0] = SECURITY_CAPABILITY_BASE_RID;
	pSid->SubAuthority[1] = SECURITY_CAPABILITY_APP_RID;
	LPDWORD lpdw = (LPDWORD)lpHashData;
	for (int i = 0; i < 8; i++) {
		pSid->SubAuthority[i + 2] = *(lpdw + i);
	}

	LocalFree(lpHashData);

	if (!IsValidSid(pSid)) {
		LocalFree(pSid);
		return NULL;
	}

	return pSid;
}

LPBYTE CreateSHA2Hash(LPWSTR lpszName)
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD      dwHashSize = 0;
	LPBYTE     lpHashData;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return NULL;

	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		CryptReleaseContext(hProv, 0);
		return NULL;
	}
	CryptHashData(hHash, (LPBYTE)lpszName, lstrlenW(lpszName) * sizeof(WCHAR), 0);

	CryptGetHashParam(hHash, HP_HASHVAL, NULL, &dwHashSize, 0);
	if (dwHashSize != 32) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return NULL;
	}
	lpHashData = (LPBYTE)LocalAlloc(LPTR, dwHashSize);
	CryptGetHashParam(hHash, HP_HASHVAL, lpHashData, &dwHashSize, 0);

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return lpHashData;
}

PSID GetPackageContentsSidFromWindowsApps()
{
	DWORD                i;
	PACL                 pDacl;
	PACCESS_ALLOWED_ACE  pAce;
	ACL_SIZE_INFORMATION aclInformation;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;
	PSID                 pSidNew = NULL;

	if (GetNamedSecurityInfo(L"C:\\Program Files\\WindowsApps", SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSecurityDescriptor) != ERROR_SUCCESS)
		return NULL;

	GetAclInformation(pDacl, &aclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

	for (i = 0; i < aclInformation.AceCount; i++) {
		GetAce(pDacl, i, (LPVOID*)& pAce);
		PSID pSidAce = (PSID)& pAce->SidStart;
		if (IsCapabilitySid(pSidAce)) {
			DWORD dwLength = GetLengthSid(pSidAce);
			pSidNew = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
			CopySid(dwLength, pSidNew, pSidAce);
			break;
		}
	}

	LocalFree(pSecurityDescriptor);

	return pSidNew;
}

BOOL IsCapabilitySid(PSID pSid)
{
	if (!IsValidSid(pSid))
		return FALSE;

	PSID_IDENTIFIER_AUTHORITY pAuthority = GetSidIdentifierAuthority(pSid);
	BYTE authority[] = SECURITY_APP_PACKAGE_AUTHORITY;

	if (pAuthority->Value[5] != authority[5])
		return FALSE;

	PDWORD pdwSubAuthority = GetSidSubAuthority(pSid, 0);

	return *pdwSubAuthority == SECURITY_CAPABILITY_BASE_RID;
}

#if 1

struct DATA {
	LPWSTR lpszFileName;
	LPWSTR lpszFolderPath;
	BOOL bFound;
};
typedef DATA* LPDATA;

int CheckAppContainerState()
{
	DATA    data;
	LPCWSTR lpszFileName = L"Calculator.exe";
	WCHAR   szFolderPath[MAX_PATH];

	data.lpszFileName = (LPWSTR)lpszFileName;
	data.lpszFolderPath = szFolderPath;
	data.bFound = FALSE;
	GetUWPFolderPathFromFileName((LPWSTR)L"C:\\Program Files\\WindowsApps", FALSE, &data);
	if (!data.bFound)
		return -1;

	WCHAR szNewFilePath[MAX_PATH];
	StringCchPrintf(szNewFilePath, ARRAYSIZE(szNewFilePath), L"%s\\%s", data.lpszFolderPath, lpszFileName);

	HANDLE hFile = CreateFile(szNewFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	CloseHandle(hFile);

	return 0;
}

void GetUWPFolderPathFromFileName(LPWSTR lpszFolderPath, BOOL bSubFolder, LPVOID lp)
{
	WCHAR           szFindPath[MAX_PATH];
	HANDLE          hFindFile;
	WIN32_FIND_DATA findData;
	LPDATA          lpData = (LPDATA)lp;

	StringCchPrintf(szFindPath, ARRAYSIZE(szFindPath), L"%s\\%s", lpszFolderPath, L"*");
	hFindFile = FindFirstFile(szFindPath, &findData);
	if (hFindFile == INVALID_HANDLE_VALUE)
		return;

	do {
		if (lpData->bFound)
			break;

		LPWSTR lpsz = findData.cFileName;
		if (lstrcmp(lpsz, L"..") != 0 && lstrcmp(lpsz, L".") != 0) {
			if (bSubFolder) {
				if (lstrcmp(lpData->lpszFileName, lpsz) == 0) {
					StringCchCopy(lpData->lpszFolderPath, MAX_PATH, lpszFolderPath);
					lpData->bFound = TRUE;
				}
			}
			else {
				if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
					continue;
				WCHAR szNewFolderPath[MAX_PATH];
				StringCchPrintf(szNewFolderPath, ARRAYSIZE(szNewFolderPath), L"%s\\%s", lpszFolderPath, findData.cFileName);
				GetUWPFolderPathFromFileName(szNewFolderPath, TRUE, lpData);
			}

		}
	} while (FindNextFile(hFindFile, &findData));

	FindClose(hFindFile);
}
#else

int CheckAppContainerState()
{
	HANDLE hToken, hTokenImpersonation;
	
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hTokenImpersonation);

	PSID pSid = CreatePackageContentsSid();

	BOOL bResult;
	CheckTokenCapability(hToken, pSid, &bResult);

	LocalFree(pSid);
	CloseHandle(hToken);
	CloseHandle(hTokenImpersonation);

	return bResult ? 0 : -1;
}

#endif


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

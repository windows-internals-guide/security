#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "wintrust.lib")

PCERT_CONTEXT GetCertContextFromFilePath(LPCWSTR lpszFilePath);

// System32フォルダに存在するexeの証明書がMicrosoft証明書でないことを確認

int main()
{
	WCHAR         szFilePath[MAX_PATH];
	PVOID         pValue;
	PCERT_CONTEXT pCertContext;
	WCHAR         szCertName[256];
	
	ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\consent.exe", szFilePath, sizeof(szFilePath) / sizeof(szFilePath[0]));

	Wow64DisableWow64FsRedirection(&pValue);
	pCertContext = GetCertContextFromFilePath(szFilePath);
	Wow64RevertWow64FsRedirection(pValue);

	if (pCertContext == NULL) {
		printf("証明書を取得できない");
		return -1;
	}

	int nExitCode = -1;

	CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szCertName, sizeof(szCertName) / sizeof(szCertName[0]));
	if (lstrcmp(szCertName, L"Microsoft Windows") == 0) {
		printf("consent.exeの証明書はWindows証明書");
		nExitCode = 0;
	}
	else
		printf("consent.exeのWindows証明書でない");

	CertFreeCertificateContext(pCertContext);

	return nExitCode;
}

PCERT_CONTEXT GetCertContextFromFilePath(LPCWSTR lpszFilePath)
{
	WINTRUST_DATA      wtd = { 0 };
	WINTRUST_FILE_INFO wtfi = { 0 };
	GUID               wvtProvGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	PCERT_CONTEXT      pCertContext = NULL;

	wtd.cbStruct = sizeof(WINTRUST_DATA);
	wtd.pPolicyCallbackData = NULL;
	wtd.pSIPClientData = NULL;
	wtd.dwUIChoice = WTD_UI_NONE;
	wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	wtd.dwUnionChoice = WTD_CHOICE_FILE;
	wtd.pFile = &wtfi;
	wtd.dwStateAction = WTD_STATEACTION_VERIFY;
	wtd.hWVTStateData = NULL;
	wtd.pwszURLReference = NULL;
	wtd.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

	wtfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
	wtfi.pcwszFilePath = lpszFilePath;
	wtfi.hFile = NULL;
	wtfi.pgKnownSubject = NULL;

	if (WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &wvtProvGuid, &wtd) == S_OK) {
		PCRYPT_PROVIDER_DATA pProvData = WTHelperProvDataFromStateData(wtd.hWVTStateData);
		if (pProvData != NULL) {
			PCRYPT_PROVIDER_SGNR pProvSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
			if (pProvSigner != NULL) {
				pCertContext = (PCERT_CONTEXT)CertDuplicateCertificateContext(pProvSigner->pChainContext->rgpChain[0]->rgpElement[0]->pCertContext);
			}
		}
	}

	wtd.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &wvtProvGuid, &wtd);

	return pCertContext;
}

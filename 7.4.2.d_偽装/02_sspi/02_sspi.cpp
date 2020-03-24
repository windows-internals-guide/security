#define  SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include <ntsecapi.h>
#include <stdio.h>

#pragma comment (lib, "secur32.lib")

BOOL StartNetworkLogon(HANDLE* phToken);
BOOL ClientHandshake(PCredHandle phCredential, PCtxtHandle phContext, PVOID* ppData, PULONG puSize, BOOL bFirst);
BOOL ServerHandshake(PCredHandle phCredential, PCtxtHandle phContext, PVOID* ppData, PULONG puSize, BOOL bFirst);
PSECURITY_LOGON_SESSION_DATA GetLogonSessionDataFromToken(HANDLE hToken);

// SSPIによる認証をした際に、ネットワーク型のログオンセッションが作成されることを確認

int main()
{
	HANDLE hToken;

	if (!StartNetworkLogon(&hToken))
		return -1;
	
	int nExitCode = -1;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData = GetLogonSessionDataFromToken(hToken);
	if (pLogonSessionData != NULL) {
		if (pLogonSessionData->LogonType == Network) {
			printf("ネットワークログオンした。");
			nExitCode = 0;
		}
	}

	CloseHandle(hToken);

	return nExitCode;
}

BOOL StartNetworkLogon(HANDLE *phToken)
{
	CredHandle              hCredentialClient, hCredentialServer;
	CtxtHandle              hContextClient, hContextServer;
	TimeStamp               ts;
	PVOID                   pData;
	ULONG                   uSize;
	BOOL                    bResult;
	WCHAR                   szUserName[] = L"kens";
	WCHAR                   szPassword[] = L"luna";
	WCHAR                   szDomainName[] = L"";
	SEC_WINNT_AUTH_IDENTITY authIdentity;

	*phToken = NULL;

	authIdentity.User = (USHORT*)szUserName;
	authIdentity.UserLength = lstrlen(szUserName);
	authIdentity.Domain = (USHORT*)szDomainName;
	authIdentity.DomainLength = lstrlen(szDomainName);
	authIdentity.Password = (USHORT*)szPassword;
	authIdentity.PasswordLength = lstrlen(szPassword);
	authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

	if (AcquireCredentialsHandle(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &authIdentity, NULL, NULL, &hCredentialClient, &ts) != SEC_E_OK) {
		printf("クライアントのクレデンシャルハンドルの取得に失敗。");
		return FALSE;
	}

	if (AcquireCredentialsHandle(NULL, (SEC_WCHAR*)L"NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &hCredentialServer, &ts) != SEC_E_OK) {
		printf("サーバーのクレデンシャルハンドルの取得に失敗。");
		FreeCredentialsHandle(&hCredentialClient);
		return FALSE;
	}

	ClientHandshake(&hCredentialClient, &hContextClient, &pData, &uSize, TRUE);
	ServerHandshake(&hCredentialServer, &hContextServer, &pData, &uSize, TRUE);
	ClientHandshake(&hCredentialClient, &hContextClient, &pData, &uSize, FALSE);
	bResult = ServerHandshake(&hCredentialServer, &hContextServer, &pData, &uSize, FALSE);
	if (bResult) {
		ImpersonateSecurityContext(&hContextServer);
		OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, phToken);
		RevertSecurityContext(&hContextServer);
	}
	else
		printf("NTLM認証に失敗した。");

	DeleteSecurityContext(&hContextClient);
	DeleteSecurityContext(&hContextServer);
	FreeCredentialsHandle(&hCredentialClient);
	FreeCredentialsHandle(&hCredentialServer);

	return *phToken != NULL;
}

BOOL ClientHandshake(PCredHandle phCredential, PCtxtHandle phContext, PVOID* ppData, PULONG puSize, BOOL bFirst)
{
	ULONG           uAttributes = 0;
	SecBuffer       sbOut[1];
	SecBuffer       sbIn[1];
	SecBufferDesc   sbdOut;
	SecBufferDesc   sbdIn;
	SECURITY_STATUS ss;

	if (!bFirst) {
		sbIn[0].pvBuffer = *ppData;
		sbIn[0].cbBuffer = *puSize;
		sbIn[0].BufferType = SECBUFFER_TOKEN;

		sbdIn.ulVersion = SECBUFFER_VERSION;
		sbdIn.cBuffers = 1;
		sbdIn.pBuffers = sbIn;
	}

	sbOut[0].cbBuffer = 0;
	sbOut[0].BufferType = SECBUFFER_TOKEN;
	sbOut[0].pvBuffer = NULL;

	sbdOut.ulVersion = SECBUFFER_VERSION;
	sbdOut.cBuffers = 1;
	sbdOut.pBuffers = sbOut;

	ss = InitializeSecurityContext(phCredential, bFirst ? NULL : phContext, NULL, uAttributes | ISC_REQ_ALLOCATE_MEMORY,
		0, SECURITY_NETWORK_DREP, bFirst ? NULL : &sbdIn, 0, phContext, &sbdOut, &uAttributes, NULL);

	if (*ppData != NULL)
		FreeContextBuffer(*ppData);

	*ppData = sbOut[0].pvBuffer;
	*puSize = sbOut[0].cbBuffer;

	return ss == SEC_E_OK;
}

BOOL ServerHandshake(PCredHandle phCredential, PCtxtHandle phContext, PVOID* ppData, PULONG puSize, BOOL bFirst)
{
	ULONG           uAttributes = 0;
	SecBuffer       sbOut[1];
	SecBuffer       sbIn[1];
	SecBufferDesc   sbdOut;
	SecBufferDesc   sbdIn;
	SECURITY_STATUS ss;

	sbIn[0].pvBuffer = *ppData;
	sbIn[0].cbBuffer = *puSize;
	sbIn[0].BufferType = SECBUFFER_TOKEN;

	sbdIn.ulVersion = SECBUFFER_VERSION;
	sbdIn.cBuffers = 1;
	sbdIn.pBuffers = sbIn;

	sbOut[0].cbBuffer = 0;
	sbOut[0].pvBuffer = NULL;
	sbOut[0].BufferType = SECBUFFER_TOKEN;

	sbdOut.ulVersion = SECBUFFER_VERSION;
	sbdOut.cBuffers = 1;
	sbdOut.pBuffers = sbOut;

	ss = AcceptSecurityContext(phCredential, bFirst ? NULL : phContext, &sbdIn, uAttributes | ASC_REQ_ALLOCATE_MEMORY,
		SECURITY_NETWORK_DREP, phContext, &sbdOut, &uAttributes, NULL);

	if (*ppData != NULL)
		FreeContextBuffer(*ppData);

	*ppData = sbOut[0].pvBuffer;
	*puSize = sbOut[0].cbBuffer;

	return ss == SEC_E_OK;
}

PSECURITY_LOGON_SESSION_DATA GetLogonSessionDataFromToken(HANDLE hToken)
{
	DWORD                        dwLength;
	PTOKEN_STATISTICS            pTokenStatistics;
	NTSTATUS                     ns;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData;

	GetTokenInformation(hToken, TokenStatistics, NULL, 0, &dwLength);
	pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLength, &dwLength);

	ns = LsaGetLogonSessionData(&pTokenStatistics->AuthenticationId, &pLogonSessionData);

	LocalFree(pTokenStatistics);

	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		return NULL;
	}

	return pLogonSessionData;
}
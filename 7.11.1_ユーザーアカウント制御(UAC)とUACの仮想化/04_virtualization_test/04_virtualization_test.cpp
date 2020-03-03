#include <stdio.h>
#include <windows.h>

#define FLAG_COPY_FILE 0x01
#define FLAG_GEN_FILE 0x02
#define FLAG_REDIRECT_STORE 0x04

int CopyExe();
int GenFile();
int CheckVirtualStore();
void EnableVirtualization(HANDLE hToken, BOOL bEnabled);

// 仮想化の有無によってリダイレクトされるかを確認

int main()
{
	HANDLE hToken;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);

	DWORD dwFlags1 = 0;
	DWORD dwFlags2 = 0;

	EnableVirtualization(hToken, FALSE);
	dwFlags1 |= CopyExe();
	dwFlags1 |= GenFile();
	if (dwFlags1 != 0) {
		printf("仮想化が無効なのにexeのコピーかファイル生成が成功した");
		return -1;
	}

	EnableVirtualization(hToken, TRUE);
	dwFlags2 |= CopyExe();
	dwFlags2 |= GenFile();

	CloseHandle(hToken);

	int nExitCode = -1;
	if (dwFlags2 == (FLAG_GEN_FILE | FLAG_REDIRECT_STORE)) {
		printf("exeのコピーは失敗し、ファイルの生成とリダイレクトを確認");
		nExitCode = 0;
	}
	else
		printf("仮想化の挙動が正しくない");

	return nExitCode;
}

int CopyExe()
{
	WCHAR szFilePath[MAX_PATH];
	ExpandEnvironmentStrings(L"%ProgramFiles%\\sample.exe", szFilePath, sizeof(szFilePath) / sizeof(WCHAR));

	WCHAR szModuleName[MAX_PATH];
	GetModuleFileName(NULL, szModuleName, MAX_PATH);
	CopyFile(szModuleName, szFilePath, FALSE);

	return GetLastError() == ERROR_SUCCESS ? FLAG_COPY_FILE : 0;
}

int GenFile()
{
	WCHAR szFilePath[256];
	ExpandEnvironmentStrings(L"%ProgramFiles%\\sample.txt", szFilePath, sizeof(szFilePath) / sizeof(WCHAR));

	HANDLE hFile = CreateFile(szFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD dwFlags = 0;
	DWORD dwError = GetLastError();
	if (dwError == ERROR_SUCCESS) {
		dwFlags = FLAG_GEN_FILE;
		dwFlags |= CheckVirtualStore();
		CloseHandle(hFile);
		DeleteFile(szFilePath);
	}

	return dwFlags;
}

int CheckVirtualStore()
{
	WCHAR szFilePath[256];
	ExpandEnvironmentStrings(L"%LocalAppData%\\VirtualStore\\Program Files (x86)\\sample.txt", szFilePath, sizeof(szFilePath) / sizeof(WCHAR));

	return GetFileAttributes(szFilePath) != INVALID_FILE_ATTRIBUTES ? FLAG_REDIRECT_STORE : 0;
}

void EnableVirtualization(HANDLE hToken, BOOL bEnabled)
{
	DWORD dwEnabled = bEnabled;

	SetTokenInformation(hToken, TokenVirtualizationEnabled, &dwEnabled, sizeof(DWORD));
}

#include <windows.h>
#include <stdio.h>
#include <shlobj.h>
#include <strsafe.h>

#define REPOSITORY_NAME L"test"
#define LOG_NAME L"autotest_log.txt"

void ScanFolder(LPWSTR lpszFolderPath, BOOL bSubFolder);
void StartProcess(LPWSTR lpszFolderPath, LPWSTR lpszFileName);
void OutputResult(HANDLE hProcess, LPWSTR lpszFolderPath);
LPWSTR GetFolderName(LPWSTR lpszFolderPath);
LPWSTR ReadRedirectString(LPCWSTR lpszFileName, LPDWORD lpdwDataSize);
HANDLE GetNormalUserToken();

BOOL IsAdminExe(LPWSTR lpszFilePath);
BOOL FindOrdinal(LPBYTE lpBaseAddress, LPCSTR lpszTargetModule, DWORD dwOrdinal);
DWORD RvaToVa(DWORD dwRva, PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_NT_HEADERS pNTHeaders);

// 自動でコンパイル済みのexeを実行していく。デスクトップ直下にリポジトリがあるものと仮定している

int main()
{
	LPWSTR lpsz;
	WCHAR  szFolderPath[MAX_PATH];

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください。");
		return -1;
	}

	SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &lpsz);
	StringCchPrintf(szFolderPath, ARRAYSIZE(szFolderPath), L"%s\\%s", lpsz, REPOSITORY_NAME);

	ScanFolder(szFolderPath, FALSE);

	CoTaskMemFree(lpsz);

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return 0;
}

void ScanFolder(LPWSTR lpszFolderPath, BOOL bSubFolder)
{
	WCHAR           szFindPath[MAX_PATH];
	HANDLE          hFindFile;
	WIN32_FIND_DATA findData;

	StringCchPrintf(szFindPath, ARRAYSIZE(szFindPath), L"%s\\%s", lpszFolderPath, L"*");
	hFindFile = FindFirstFile(szFindPath, &findData);

	do {
		LPWSTR lpsz = findData.cFileName;
		if (lstrcmp(lpsz, L"..") != 0 && lstrcmp(lpsz, L".") != 0 && lstrcmp(lpsz, L"auto_build") != 0 && lstrcmp(lpsz, L"auto_exec") != 0) {
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				WCHAR szNewFolderPath[MAX_PATH];
				StringCchPrintf(szNewFolderPath, ARRAYSIZE(szNewFolderPath), L"%s\\%s", lpszFolderPath, findData.cFileName);
				if (bSubFolder)
					StartProcess(szNewFolderPath, findData.cFileName);
				else
					ScanFolder(szNewFolderPath, TRUE);
			}
		}
	} while (FindNextFile(hFindFile, &findData));

	FindClose(hFindFile);
}

void StartProcess(LPWSTR lpszFolderPath, LPWSTR lpszFileName)
{
	WCHAR               szModuleName[MAX_PATH];
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;

	StringCchPrintf(szModuleName, ARRAYSIZE(szModuleName), L"%s\\%s.exe", lpszFolderPath, lpszFileName);

	if (GetFileAttributes(szModuleName) == INVALID_FILE_ATTRIBUTES) {
		HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hStdOutput, FOREGROUND_GREEN);

		WCHAR szData[MAX_PATH];
		StringCchPrintf(szData, ARRAYSIZE(szData), L"ファイルが見つからない %s\n", lpszFileName);

		DWORD dwWriteByte;
		WriteConsole(hStdOutput, szData, lstrlen(szData), &dwWriteByte, NULL);
		return;
	}

	HANDLE hFileOut;
	HANDLE hStdOutput;

	hFileOut = CreateFile(LOG_NAME, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DuplicateHandle(GetCurrentProcess(), hFileOut, GetCurrentProcess(), &hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS);

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.dwFlags = STARTF_USESTDHANDLES;
	startupInfo.hStdOutput = hStdOutput;

	WCHAR szDirectoryPath[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, szDirectoryPath);

	if (IsAdminExe(szModuleName)) {
		CreateProcess(szModuleName, NULL, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, szDirectoryPath, &startupInfo, &processInformation);
	}
	else {
		HANDLE hTokenMedium = GetNormalUserToken();

		startupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";
		CreateProcessWithTokenW(hTokenMedium, 0, szModuleName, NULL, CREATE_NO_WINDOW, NULL, szDirectoryPath, &startupInfo, &processInformation);

		CloseHandle(hTokenMedium);
	}

	DWORD dwResult = WaitForSingleObject(processInformation.hProcess, 5000);

	CloseHandle(hFileOut);
	CloseHandle(hStdOutput);

	if (dwResult == WAIT_OBJECT_0) {
		OutputResult(processInformation.hProcess, lpszFolderPath);
	}

	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);
}

void OutputResult(HANDLE hProcess, LPWSTR lpszFolderPath)
{
	DWORD dwExitCode;
	WCHAR szData[MAX_PATH];
	LPWSTR lpszFolderName = GetFolderName(lpszFolderPath);

	GetExitCodeProcess(hProcess, &dwExitCode);
	if (dwExitCode == 0) {
		StringCchPrintf(szData, ARRAYSIZE(szData), L"%s [%s]\n", L"成功", lpszFolderName);
	}
	else {
		DWORD dwDataSize;
		LPWSTR lpsz = ReadRedirectString(LOG_NAME, &dwDataSize);
		StringCchPrintf(szData, ARRAYSIZE(szData), L"%s [%s] %s\n", L"失敗", lpszFolderName, lpsz);
		LocalFree(lpsz);
	}

	HANDLE hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	if (dwExitCode == 0) {
		SetConsoleTextAttribute(hStdOutput, FOREGROUND_INTENSITY);
	}
	else {
		SetConsoleTextAttribute(hStdOutput, FOREGROUND_RED);
	}
	DWORD dwWriteByte;
	WriteConsole(hStdOutput, szData, lstrlen(szData), &dwWriteByte, NULL);
}

LPWSTR GetFolderName(LPWSTR lpszFolderPath)
{
	int i;
	int n = 0;

	for (i = lstrlen(lpszFolderPath) - 1; i > 0; i--) {
		if (lpszFolderPath[i] == '\\') {
			if (++n == 2)
				return &lpszFolderPath[i + 1];
		}
	}

	return lpszFolderPath;
}

LPWSTR ReadRedirectString(LPCWSTR lpszFileName, LPDWORD lpdwDataSize)
{
	HANDLE hFile;
	DWORD  dwReadByte, dwFileSize;
	LPBYTE lpBuffer;

	hFile = CreateFile(lpszFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	dwFileSize = GetFileSize(hFile, NULL);
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, dwFileSize);
	ReadFile(hFile, lpBuffer, dwFileSize, &dwReadByte, NULL);

	CloseHandle(hFile);

	*lpdwDataSize = dwFileSize;

	DWORD dwSize = dwFileSize * sizeof(WCHAR);
	LPWSTR lpwsz = (LPWSTR)LocalAlloc(LPTR, dwSize);

	MultiByteToWideChar(CP_ACP, 0, (LPSTR)lpBuffer, dwFileSize, lpwsz, dwSize);

	LocalFree(lpBuffer);

	return lpwsz;
}

HANDLE GetNormalUserToken()
{
	DWORD  dwProcessId;
	HANDLE hProcess;
	HANDLE hTokenNormal, hTokenDuplicate;

	GetWindowThreadProcessId(GetShellWindow(), &dwProcessId);
	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwProcessId);
	if (hProcess == NULL)
		return NULL;

	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hTokenNormal)) {
		CloseHandle(hProcess);
		return NULL;
	}

	DuplicateTokenEx(hTokenNormal, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &hTokenDuplicate);

	CloseHandle(hProcess);
	CloseHandle(hTokenNormal);

	return hTokenDuplicate;
}

BOOL IsAdminExe(LPWSTR lpszFilePath)
{
	HANDLE hFile;

	hFile = CreateFile(lpszFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	DWORD dwReadByte;
	LPBYTE lpFileData = (LPBYTE)LocalAlloc(LPTR, dwFileSize);

	ReadFile(hFile, lpFileData, dwFileSize, &dwReadByte, NULL);
	CloseHandle(hFile);

	// exeファイルのIATにてSHTestTokenMembershipの序数(245)が見つかったら、そのexeは管理者権限を要求していると判断できる
	BOOL bResult = FindOrdinal(lpFileData, "SHELL32.dll", 245);

	LocalFree(lpFileData);

	return bResult;
}

BOOL FindOrdinal(LPBYTE lpBaseAddress, LPCSTR lpszTargetModule, DWORD dwOrdinal)
{
	PIMAGE_NT_HEADERS     pNTHeaders = (PIMAGE_NT_HEADERS)(lpBaseAddress + PIMAGE_DOS_HEADER(lpBaseAddress)->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaders);

	if (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return FALSE;

	DWORD                    dwOffset = RvaToVa(pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSectionHeader, pNTHeaders);
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpBaseAddress + dwOffset);

	while (pImportDescriptor->Name != NULL) {
		LPSTR lpszModuleName = (LPSTR)(lpBaseAddress + RvaToVa(pImportDescriptor->Name, pSectionHeader, pNTHeaders));

		if (lstrcmpiA(lpszModuleName, lpszTargetModule) != 0) {
			pImportDescriptor++;
			continue;
		}

		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(lpBaseAddress + RvaToVa(pImportDescriptor->OriginalFirstThunk, pSectionHeader, pNTHeaders));
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(lpBaseAddress + RvaToVa(pImportDescriptor->FirstThunk, pSectionHeader, pNTHeaders));

		while (pINT->u1.AddressOfData != 0 && pIAT->u1.Function != 0) {
			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal)) {
				if (IMAGE_ORDINAL(pINT->u1.Ordinal) == dwOrdinal)
					return TRUE;
			}
			else {
				PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)(lpBaseAddress + RvaToVa(pINT->u1.AddressOfData, pSectionHeader, pNTHeaders));
				// printf("\t %d %s\n", pFuncName->Hint, pFuncName->Name);
			}

			pINT++;
			pIAT++;
		}

		pImportDescriptor++;
	}

	return FALSE;
}

DWORD RvaToVa(DWORD dwRva, PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_NT_HEADERS pNTHeaders)
{
	if (dwRva == 0)
		return dwRva;

	WORD i;
	for (i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
		if (dwRva >= pSectionHeader->VirtualAddress && dwRva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
			break;
		pSectionHeader++;
	}

	return (dwRva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
}
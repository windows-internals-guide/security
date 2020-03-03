#include <stdio.h>
#include <windows.h>

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);

// ウインドウがデスクトップ単位で存在することを確認

int main()
{
	int nCount1 = 0;
	int nCount2 = 0;

	EnumWindows(EnumWindowsProc, (LPARAM)& nCount1);

	// 現在アクティブなデスクトップのハンドルを取得
	HDESK hCurrentDesktop = OpenInputDesktop(0, FALSE, GENERIC_ALL);

	// 新しいデスクトップを作成
	HDESK hNewDesktop = CreateDesktop(L"NewDesktop", NULL, NULL, 0, GENERIC_ALL, NULL);

	// スレッドに新しく作成したデスクトップを関連付ける
	SetThreadDesktop(hNewDesktop);
	EnumWindows(EnumWindowsProc, (LPARAM)& nCount2);
	SetThreadDesktop(hCurrentDesktop);

	int nExitCode = -1;
	if (nCount2 == 0) {
		printf("現在のデスクトップのウインドウ数 %d\n", nCount1);
		printf("新規のデスクトップのウインドウ数 %d", nCount2);
		nExitCode = 0;
	}
	else
		printf("新規のデスクトップに何故かウインドウが存在 %d", nCount2);

	CloseDesktop(hNewDesktop);

	return nExitCode;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	int* pn = (int*)lParam;

	*pn += 1;

	return TRUE;
}
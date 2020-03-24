#define INITGUID
#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>

BOOL SetAuditPolicy(BOOL bEnabled);
ULONG GetEnabledSubCategoryCount();

// 監査ポリシーを有効にするとサブカテゴリも有効になることを確認

int main()
{
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください。");
		return 0;
	}

	ULONG uCount1, uCount2;

	uCount1 = GetEnabledSubCategoryCount();

	SetAuditPolicy(TRUE);
	uCount2 = GetEnabledSubCategoryCount();
	SetAuditPolicy(FALSE);

	int nExitCode = -1;

	if (uCount1 == 0 && uCount2 == 3) {
		printf("サブカテゴリへの反映を確認");
		nExitCode = 0;
	}
	else
		printf("サブカテゴリへの反映を確認できない");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

BOOL SetAuditPolicy(BOOL bEnabled)
{
	NTSTATUS                  ns;
	LSA_HANDLE                hPolicy;
	LSA_OBJECT_ATTRIBUTES     objectAttributes;
	PPOLICY_AUDIT_EVENTS_INFO pAuditInfo;
	DWORD                     dwEventOption = bEnabled ? POLICY_AUDIT_EVENT_SUCCESS : POLICY_AUDIT_EVENT_NONE;

	ZeroMemory(&objectAttributes, sizeof(LSA_OBJECT_ATTRIBUTES));
	objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

	ns = LsaOpenPolicy(NULL, &objectAttributes, POLICY_VIEW_AUDIT_INFORMATION | POLICY_SET_AUDIT_REQUIREMENTS, &hPolicy);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS)
		return FALSE;

	LsaQueryInformationPolicy(hPolicy, PolicyAuditEventsInformation, (LPVOID*)& pAuditInfo);

	pAuditInfo->EventAuditingOptions[AuditCategoryPrivilegeUse] = dwEventOption;
	LsaSetInformationPolicy(hPolicy, PolicyAuditEventsInformation, (LPVOID)pAuditInfo);

	LsaFreeMemory(pAuditInfo);
	LsaClose(hPolicy);

	return TRUE;
}

ULONG GetEnabledSubCategoryCount()
{
	ULONG                     i, uTotal = 0;
	GUID* pGuidSubCategory;
	ULONG                     uSubCategoryCount;
	PAUDIT_POLICY_INFORMATION pAuditPolicy;

	AuditEnumerateSubCategories(&Audit_PrivilegeUse, FALSE, &pGuidSubCategory, &uSubCategoryCount);

	AuditQuerySystemPolicy(pGuidSubCategory, uSubCategoryCount, &pAuditPolicy);

	for (i = 0; i < uSubCategoryCount; i++) {
		if (pAuditPolicy[i].AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS)
			uTotal++;
	}

	AuditFree(pAuditPolicy);
	AuditFree(pGuidSubCategory);

	return uTotal;
}

// printfに効果ない
void ShowSubCategoryName()
{
	ULONG  i, uTotal = 0;
	LPWSTR lpszSubCategoryName;
	GUID* pGuidSubCategory;
	ULONG  uSubCategoryCount;

	AuditEnumerateSubCategories(&Audit_PrivilegeUse, FALSE, &pGuidSubCategory, &uSubCategoryCount);

	for (i = 0; i < uSubCategoryCount; i++) {
		AuditLookupSubCategoryName(&pGuidSubCategory[i], &lpszSubCategoryName);
		printf("%ws\n", lpszSubCategoryName); // MessageBox(NULL, lpszSubCategoryName, L"OK", MB_OK);
		AuditFree(lpszSubCategoryName);
	}

	AuditFree(pGuidSubCategory);
}

#pragma once

#include <fltKernel.h>
#include "Shared.h"

typedef struct _FILE_PROTECTION_STATE {
    BOOLEAN Initialized;
    UNICODE_STRING ProtectedDriverOpenPath;
    UNICODE_STRING CanonicalProtectedDriverPath;
    WCHAR CanonicalProtectedDriverPathBuffer[MAX_REG_PATH_LENGTH];
} FILE_PROTECTION_STATE, *PFILE_PROTECTION_STATE;

typedef struct _FILE_PROTECTION_RUNTIME_STATS {
    ULONG64 BlockCount;
    ULONG64 CreateBlockCount;
    ULONG64 SetInformationBlockCount;
    WCHAR LastInfoClass[MAX_RULE_LENGTH];
} FILE_PROTECTION_RUNTIME_STATS, *PFILE_PROTECTION_RUNTIME_STATS;

NTSTATUS InitializeFileProtectionState();
VOID CleanupFileProtectionState();
VOID GetFileProtectionRuntimeStats(_Out_ PFILE_PROTECTION_RUNTIME_STATS runtimeStats);

FLT_PREOP_CALLBACK_STATUS FileProtectionPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS FileProtectionPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

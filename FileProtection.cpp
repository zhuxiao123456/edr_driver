#include "PebMonitor.h"

static FILE_PROTECTION_STATE g_FileProtectionState = {};
static const WCHAR g_ProtectedDriverOpenPathBuffer[] = L"\\SystemRoot\\System32\\drivers\\DriverModule.sys";
static const WCHAR g_FileProtectionRuleId[] = L"driver_self_protection";
static const WCHAR g_FileProtectionCreateInfoClassName[] = L"IRP_MJ_CREATE";
static volatile LONG64 g_FileProtectionBlockCount = 0;
static volatile LONG64 g_FileProtectionCreateBlockCount = 0;
static volatile LONG64 g_FileProtectionSetInformationBlockCount = 0;
static KSPIN_LOCK g_FileProtectionRuntimeStatsLock = {};
static WCHAR g_LastFileProtectionInfoClass[MAX_RULE_LENGTH] = {};

EXTERN_C PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

static VOID CopyAnsiProcessNameToWideBuffer(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_opt_z_ PCSTR source) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (source == NULL || source[0] == '\0') {
        return;
    }

    SIZE_T writeIndex = 0;
    while (writeIndex + 1 < bufferLength && source[writeIndex] != '\0') {
        CHAR character = source[writeIndex];
        if (character >= 'A' && character <= 'Z') {
            character = (CHAR)(character - 'A' + 'a');
        }

        buffer[writeIndex] = (WCHAR)(UCHAR)character;
        writeIndex++;
    }

    buffer[writeIndex] = L'\0';
}

static VOID CopyWideStringToFixedBuffer(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_opt_z_ PCWSTR source) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (source == NULL || source[0] == L'\0') {
        return;
    }

    NTSTATUS status = RtlStringCchCopyW(buffer, bufferLength, source);
    if (!NT_SUCCESS(status)) {
        buffer[bufferLength - 1] = L'\0';
    }
}

static VOID CopyUnicodeStringToFixedBuffer(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_opt_ PCUNICODE_STRING source) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0) {
        return;
    }

    ULONG copyBytes = source->Length;
    ULONG maxBytes = (ULONG)((bufferLength - 1) * sizeof(WCHAR));
    if (copyBytes > maxBytes) {
        copyBytes = maxBytes;
    }

    copyBytes -= (copyBytes % sizeof(WCHAR));
    if (copyBytes == 0) {
        return;
    }

    RtlCopyMemory(buffer, source->Buffer, copyBytes);
    buffer[copyBytes / sizeof(WCHAR)] = L'\0';
}

static ULONG64 ReadInterlockedCounter64(_In_ volatile LONG64* value) {
    return (ULONG64)InterlockedCompareExchange64(value, 0, 0);
}

static VOID InitializeUnicodeStringBuffer(
    _Out_ PUNICODE_STRING target,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength) {
    if (target == NULL || buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    target->Buffer = buffer;
    target->Length = 0;
    target->MaximumLength = (USHORT)(bufferLength * sizeof(WCHAR));
}

static NTSTATUS CopyUnicodeStringToStateBuffer(
    _Out_ PUNICODE_STRING target,
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_ PCUNICODE_STRING source) {
    if (target == NULL || buffer == NULL || bufferLength == 0 || source == NULL || source->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeUnicodeStringBuffer(target, buffer, bufferLength);

    ULONG copyBytes = source->Length;
    ULONG maxBytes = (ULONG)((bufferLength - 1) * sizeof(WCHAR));
    if (copyBytes > maxBytes) {
        copyBytes = maxBytes;
    }

    copyBytes -= (copyBytes % sizeof(WCHAR));
    if (copyBytes == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(buffer, source->Buffer, copyBytes);
    buffer[copyBytes / sizeof(WCHAR)] = L'\0';
    target->Length = (USHORT)copyBytes;
    return STATUS_SUCCESS;
}

static VOID ResetFileProtectionRuntimeStats() {
    InterlockedExchange64(&g_FileProtectionBlockCount, 0);
    InterlockedExchange64(&g_FileProtectionCreateBlockCount, 0);
    InterlockedExchange64(&g_FileProtectionSetInformationBlockCount, 0);
    KeInitializeSpinLock(&g_FileProtectionRuntimeStatsLock);
    RtlZeroMemory(g_LastFileProtectionInfoClass, sizeof(g_LastFileProtectionInfoClass));
}

static VOID RecordFileProtectionBlock(_In_opt_z_ PCWSTR infoClassName) {
    PCWSTR effectiveInfoClassName = infoClassName;
    if (effectiveInfoClassName == NULL || effectiveInfoClassName[0] == L'\0') {
        effectiveInfoClassName = g_FileProtectionCreateInfoClassName;
        InterlockedIncrement64(&g_FileProtectionCreateBlockCount);
    }
    else {
        InterlockedIncrement64(&g_FileProtectionSetInformationBlockCount);
    }

    InterlockedIncrement64(&g_FileProtectionBlockCount);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FileProtectionRuntimeStatsLock, &oldIrql);
    CopyWideStringToFixedBuffer(
        g_LastFileProtectionInfoClass,
        RTL_NUMBER_OF(g_LastFileProtectionInfoClass),
        effectiveInfoClassName);
    KeReleaseSpinLock(&g_FileProtectionRuntimeStatsLock, oldIrql);
}

static BOOLEAN IsDangerousCreateRequest(_In_ PFLT_CALLBACK_DATA Data) {
    if (Data == NULL || Data->Iopb == NULL) {
        return FALSE;
    }

    ACCESS_MASK desiredAccess = 0;
    PIO_SECURITY_CONTEXT securityContext = Data->Iopb->Parameters.Create.SecurityContext;
    if (securityContext != NULL) {
        desiredAccess = securityContext->DesiredAccess;
    }

    ULONG createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;

    if ((desiredAccess & (DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | WRITE_DAC | WRITE_OWNER)) != 0) {
        return TRUE;
    }

    if ((createOptions & FILE_DELETE_ON_CLOSE) != 0) {
        return TRUE;
    }

    return (createDisposition == FILE_SUPERSEDE ||
        createDisposition == FILE_OVERWRITE ||
        createDisposition == FILE_OVERWRITE_IF);
}

static BOOLEAN IsDangerousSetInformationClass(_In_ FILE_INFORMATION_CLASS fileInformationClass) {
    return (fileInformationClass == FileDispositionInformation ||
        fileInformationClass == FileDispositionInformationEx ||
        fileInformationClass == FileRenameInformation ||
        fileInformationClass == FileRenameInformationEx);
}

static PCWSTR GetSetInformationClassName(_In_ FILE_INFORMATION_CLASS fileInformationClass) {
    switch (fileInformationClass) {
    case FileDispositionInformation:
        return L"FileDispositionInformation";
    case FileDispositionInformationEx:
        return L"FileDispositionInformationEx";
    case FileRenameInformation:
        return L"FileRenameInformation";
    case FileRenameInformationEx:
        return L"FileRenameInformationEx";
    default:
        return L"UnknownFileSetInformationClass";
    }
}

static BOOLEAN IsProtectedDriverPath(_In_ PCUNICODE_STRING normalizedName) {
    if (!g_FileProtectionState.Initialized ||
        normalizedName == NULL ||
        normalizedName->Buffer == NULL ||
        g_FileProtectionState.CanonicalProtectedDriverPath.Buffer == NULL ||
        g_FileProtectionState.CanonicalProtectedDriverPath.Length == 0) {
        return FALSE;
    }

    return RtlEqualUnicodeString(
        normalizedName,
        &g_FileProtectionState.CanonicalProtectedDriverPath,
        TRUE);
}

static VOID QueueBlockedFileProtectionEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING normalizedName,
    _In_opt_z_ PCWSTR infoClassName) {
    PDRIVER_EVENT_NODE node = AllocateDriverEventNode();
    if (node == NULL) {
        InterlockedIncrement64(&g_DriverEventAllocFailCount);
        return;
    }

    node->EventData.EventType = DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION;
    node->EventData.Severity = 100;
    CopyWideStringToFixedBuffer(
        node->EventData.RuleId,
        RTL_NUMBER_OF(node->EventData.RuleId),
        g_FileProtectionRuleId);
    CopyUnicodeStringToFixedBuffer(
        node->EventData.TargetPath,
        RTL_NUMBER_OF(node->EventData.TargetPath),
        normalizedName);
    CopyWideStringToFixedBuffer(
        node->EventData.InfoClass,
        RTL_NUMBER_OF(node->EventData.InfoClass),
        infoClassName);

    PEPROCESS requestorProcess = FltGetRequestorProcess(Data);
    if (requestorProcess != NULL) {
        node->EventData.ProcessId = HandleToULong(PsGetProcessId(requestorProcess));
        CopyAnsiProcessNameToWideBuffer(
            node->EventData.ProcessName,
            RTL_NUMBER_OF(node->EventData.ProcessName),
            PsGetProcessImageFileName(requestorProcess));
    }

    QueueDriverEventNode(node);
}

static FLT_PREOP_CALLBACK_STATUS CompleteBlockedProtectedFileRequest(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING normalizedName,
    _In_opt_z_ PCWSTR infoClassName) {
    RecordFileProtectionBlock(infoClassName);
    QueueBlockedFileProtectionEvent(Data, normalizedName, infoClassName);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static NTSTATUS ResolveCanonicalProtectedDriverPath() {
    if (g_FilterHandle == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    OBJECT_ATTRIBUTES objectAttributes = {};
    IO_STATUS_BLOCK ioStatus = {};
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    InitializeObjectAttributes(
        &objectAttributes,
        &g_FileProtectionState.ProtectedDriverOpenPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    NTSTATUS status = FltCreateFileEx2(
        g_FilterHandle,
        NULL,
        &fileHandle,
        &fileObject,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        0,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltGetFileNameInformationUnsafe(
        fileObject,
        NULL,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            status = CopyUnicodeStringToStateBuffer(
                &g_FileProtectionState.CanonicalProtectedDriverPath,
                g_FileProtectionState.CanonicalProtectedDriverPathBuffer,
                RTL_NUMBER_OF(g_FileProtectionState.CanonicalProtectedDriverPathBuffer),
                &nameInfo->Name);
        }
    }

    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
    }
    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }
    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }

    return status;
}

NTSTATUS InitializeFileProtectionState() {
    RtlZeroMemory(&g_FileProtectionState, sizeof(g_FileProtectionState));
    ResetFileProtectionRuntimeStats();
    RtlInitUnicodeString(
        &g_FileProtectionState.ProtectedDriverOpenPath,
        g_ProtectedDriverOpenPathBuffer);

    InitializeUnicodeStringBuffer(
        &g_FileProtectionState.CanonicalProtectedDriverPath,
        g_FileProtectionState.CanonicalProtectedDriverPathBuffer,
        RTL_NUMBER_OF(g_FileProtectionState.CanonicalProtectedDriverPathBuffer));

    NTSTATUS status = ResolveCanonicalProtectedDriverPath();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[PebMonitor] ERR: Failed to resolve canonical protected-driver path. Status=0x%08X\n", status));
        return status;
    }

    g_FileProtectionState.Initialized = TRUE;
    KdPrint(("[PebMonitor] INFO: Canonical protected-driver path resolved: %wZ\n",
        &g_FileProtectionState.CanonicalProtectedDriverPath));
    return STATUS_SUCCESS;
}

VOID CleanupFileProtectionState() {
    ResetFileProtectionRuntimeStats();
    RtlZeroMemory(&g_FileProtectionState, sizeof(g_FileProtectionState));
}

VOID GetFileProtectionRuntimeStats(_Out_ PFILE_PROTECTION_RUNTIME_STATS runtimeStats) {
    if (runtimeStats == NULL) {
        return;
    }

    RtlZeroMemory(runtimeStats, sizeof(*runtimeStats));
    runtimeStats->BlockCount = ReadInterlockedCounter64(&g_FileProtectionBlockCount);
    runtimeStats->CreateBlockCount = ReadInterlockedCounter64(&g_FileProtectionCreateBlockCount);
    runtimeStats->SetInformationBlockCount = ReadInterlockedCounter64(&g_FileProtectionSetInformationBlockCount);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FileProtectionRuntimeStatsLock, &oldIrql);
    CopyWideStringToFixedBuffer(
        runtimeStats->LastInfoClass,
        RTL_NUMBER_OF(runtimeStats->LastInfoClass),
        g_LastFileProtectionInfoClass);
    KeReleaseSpinLock(&g_FileProtectionRuntimeStatsLock, oldIrql);
}

FLT_PREOP_CALLBACK_STATUS FileProtectionPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_FileProtectionState.Initialized || Data == NULL || Data->Iopb == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->RequestorMode == KernelMode || !IsDangerousCreateRequest(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    BOOLEAN blockRequest = FALSE;
    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status) && IsProtectedDriverPath(&nameInfo->Name)) {
        blockRequest = TRUE;
    }

    if (blockRequest) {
        KdPrint(("[PebMonitor] WARN: Blocking write/delete access to protected driver file.\n"));
        FLT_PREOP_CALLBACK_STATUS result = CompleteBlockedProtectedFileRequest(
            Data,
            &nameInfo->Name,
            NULL);
        FltReleaseFileNameInformation(nameInfo);
        return result;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FileProtectionPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_FileProtectionState.Initialized || Data == NULL || Data->Iopb == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FILE_INFORMATION_CLASS fileInformationClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (Data->RequestorMode == KernelMode || !IsDangerousSetInformationClass(fileInformationClass)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    BOOLEAN blockRequest = FALSE;
    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status) && IsProtectedDriverPath(&nameInfo->Name)) {
        blockRequest = TRUE;
    }

    if (blockRequest) {
        KdPrint(("[PebMonitor] WARN: Blocking delete/rename set-information access to protected driver file.\n"));
        FLT_PREOP_CALLBACK_STATUS result = CompleteBlockedProtectedFileRequest(
            Data,
            &nameInfo->Name,
            GetSetInformationClassName(fileInformationClass));
        FltReleaseFileNameInformation(nameInfo);
        return result;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

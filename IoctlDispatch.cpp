#include "PebMonitor.h"

EXTERN_C POBJECT_TYPE* PsProcessType;
EXTERN_C PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

static const ULONG kRuleBatchPoolTag = 'bRgR';

static const UNICODE_STRING g_ProtectedProcessPathSuffixes[] = {
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\smss.exe"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\csrss.exe"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\wininit.exe"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\winlogon.exe"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\services.exe"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\lsass.exe"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\svchost.exe"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\dwm.exe"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\spoolsv.exe")
};

static const CHAR* const g_ProtectedProcessShortNames[] = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "spoolsv.exe"
};

static ULONGLONG ReadInterlockedCounter64(_In_ volatile LONG64* counter) {
    return (ULONGLONG)InterlockedCompareExchange64(counter, 0, 0);
}

static ULONG ReadInterlockedFlags(_In_ volatile LONG* value) {
    return (ULONG)InterlockedCompareExchange(value, 0, 0);
}

static VOID SanitizeRegistryRule(_Inout_ PREGISTRY_RULE rule) {
    if (rule == NULL) {
        return;
    }

    rule->RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
    rule->ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
    rule->KeyPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
    rule->InfoClass[MAX_RULE_LENGTH - 1] = L'\0';
    rule->ValueName[MAX_RULE_LENGTH - 1] = L'\0';
    rule->ValueData[MAX_RULE_LENGTH - 1] = L'\0';
}

static VOID FreeSanitizedRegistryRuleBatch(_In_opt_ PREGISTRY_RULE rules) {
    if (rules != NULL) {
        ExFreePoolWithTag(rules, kRuleBatchPoolTag);
    }
}

static NTSTATUS CaptureSanitizedRegistryRuleBatch(
    _In_reads_bytes_(inputBufferLength) const VOID* inputBuffer,
    _In_ ULONG inputBufferLength,
    _Outptr_result_buffer_maybenull_(*outRuleCount) PREGISTRY_RULE* outRules,
    _Out_ PULONG outRuleCount) {
    if (outRules == NULL || outRuleCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *outRules = NULL;
    *outRuleCount = 0;

    const SIZE_T headerSize = FIELD_OFFSET(REGISTRY_RULE_BATCH_UPDATE, Rules);
    if (inputBuffer == NULL || inputBufferLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    const REGISTRY_RULE_BATCH_UPDATE* batchUpdate =
        (const REGISTRY_RULE_BATCH_UPDATE*)inputBuffer;
    if (!PEBMONITOR_ABI_IS_COMPAT(batchUpdate->AbiVersion)) {
        return STATUS_REVISION_MISMATCH;
    }

    const ULONG ruleCount = batchUpdate->RuleCount;
    const SIZE_T ruleBytes = sizeof(REGISTRY_RULE) * (SIZE_T)ruleCount;
    const SIZE_T requiredSize = headerSize + ruleBytes;
    if ((SIZE_T)inputBufferLength < requiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (ruleCount == 0) {
        return STATUS_SUCCESS;
    }

    PREGISTRY_RULE sanitizedRules =
        (PREGISTRY_RULE)ExAllocatePoolZero(NonPagedPoolNx, ruleBytes, kRuleBatchPoolTag);
    if (sanitizedRules == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(sanitizedRules, batchUpdate->Rules, ruleBytes);
    for (ULONG index = 0; index < ruleCount; ++index) {
        SanitizeRegistryRule(&sanitizedRules[index]);
    }

    *outRules = sanitizedRules;
    *outRuleCount = ruleCount;
    return STATUS_SUCCESS;
}

static ULONG QueryRuleStoreRuleCount(_In_ PRULE_STORE volatile* currentStore) {
    PRULE_STORE snapshot = NULL;
    ULONG count = 0;

    AcquireRuleStoreSnapshot(currentStore, &snapshot);
    count = GetRuleStoreTotalRuleCount(snapshot);
    ReleaseRuleStoreSnapshot(snapshot);
    return count;
}

static VOID QueryRuleStoreBucketCounts(
    _In_ PRULE_STORE volatile* currentStore,
    _Out_ PULONG exactCount,
    _Out_ PULONG prefixCount,
    _Out_ PULONG suffixCount,
    _Out_ PULONG containsCount) {
    PRULE_STORE snapshot = NULL;
    ULONG localExactCount = 0;
    ULONG localPrefixCount = 0;
    ULONG localSuffixCount = 0;
    ULONG localContainsCount = 0;

    AcquireRuleStoreSnapshot(currentStore, &snapshot);
    if (snapshot != NULL) {
        localExactCount = snapshot->ExactRuleCount;
        localPrefixCount = snapshot->PrefixRuleCount;
        localSuffixCount = snapshot->SuffixRuleCount;
        localContainsCount = snapshot->ContainsRuleCount;
    }
    ReleaseRuleStoreSnapshot(snapshot);

    *exactCount = localExactCount;
    *prefixCount = localPrefixCount;
    *suffixCount = localSuffixCount;
    *containsCount = localContainsCount;
}

static CHAR ToLowerAnsiCharacter(_In_ CHAR character) {
    if (character >= 'A' && character <= 'Z') {
        return (CHAR)(character - 'A' + 'a');
    }

    return character;
}

static BOOLEAN AsciiEqualsInsensitive(_In_opt_z_ PCSTR left, _In_opt_z_ PCSTR right) {
    if (left == NULL || right == NULL) {
        return FALSE;
    }

    ULONG index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        if (ToLowerAnsiCharacter(left[index]) != ToLowerAnsiCharacter(right[index])) {
            return FALSE;
        }
        index++;
    }

    return left[index] == '\0' && right[index] == '\0';
}

static VOID CopyAnsiStringToWideBuffer(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_opt_z_ PCSTR source) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (source == NULL) {
        return;
    }

    SIZE_T index = 0;
    while (index + 1 < bufferLength && source[index] != '\0') {
        CHAR character = ToLowerAnsiCharacter(source[index]);
        buffer[index] = (WCHAR)(UCHAR)character;
        index++;
    }

    buffer[index] = L'\0';
}

static VOID CopyWideStringToFixedBuffer(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_opt_z_ PCWSTR source) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (source == NULL) {
        return;
    }

    SIZE_T index = 0;
    while (index + 1 < bufferLength && source[index] != L'\0') {
        buffer[index] = source[index];
        index++;
    }

    buffer[index] = L'\0';
}

static VOID CopyUnicodeFileNameToFixedBuffer(
    _Out_writes_(bufferLength) WCHAR* buffer,
    _In_ SIZE_T bufferLength,
    _In_opt_ PCUNICODE_STRING path) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }

    buffer[0] = L'\0';
    if (path == NULL || path->Buffer == NULL || path->Length == 0) {
        return;
    }

    USHORT startIndex = 0;
    USHORT characterCount = (USHORT)(path->Length / sizeof(WCHAR));
    for (USHORT index = 0; index < characterCount; ++index) {
        if (path->Buffer[index] == L'\\' || path->Buffer[index] == L'/') {
            startIndex = (USHORT)(index + 1);
        }
    }

    SIZE_T writeIndex = 0;
    while (writeIndex + 1 < bufferLength && (startIndex + writeIndex) < characterCount) {
        buffer[writeIndex] = path->Buffer[startIndex + writeIndex];
        writeIndex++;
    }

    buffer[writeIndex] = L'\0';
}

static BOOLEAN IsProtectedShortImageName(_In_opt_z_ PCSTR imageName) {
    if (imageName == NULL || imageName[0] == '\0') {
        return FALSE;
    }

    for (ULONG index = 0; index < RTL_NUMBER_OF(g_ProtectedProcessShortNames); ++index) {
        if (AsciiEqualsInsensitive(imageName, g_ProtectedProcessShortNames[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN IsProtectedFullImagePath(_In_ PCUNICODE_STRING imagePath) {
    if (imagePath == NULL || imagePath->Buffer == NULL || imagePath->Length == 0) {
        return FALSE;
    }

    for (ULONG index = 0; index < RTL_NUMBER_OF(g_ProtectedProcessPathSuffixes); ++index) {
        if (RtlSuffixUnicodeString(&g_ProtectedProcessPathSuffixes[index], imagePath, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID QueueResponseActionEvent(
    _In_ ULONG responseAction,
    _In_ ULONG processId,
    _In_opt_z_ PCWSTR processName,
    _In_ NTSTATUS responseStatus) {
    PDRIVER_EVENT_NODE node = AllocateDriverEventNode();
    if (node == NULL) {
        InterlockedIncrement64(&g_DriverEventAllocFailCount);
        return;
    }

    node->EventData.EventType = DRIVER_EVENT_TYPE_RESPONSE_ACTION;
    node->EventData.ProcessId = processId;
    node->EventData.ResponseAction = responseAction;
    node->EventData.ResponseStatus = responseStatus;
    CopyWideStringToFixedBuffer(
        node->EventData.ProcessName,
        RTL_NUMBER_OF(node->EventData.ProcessName),
        processName);

    KIRQL oldIrql;
    PIRP irpToComplete = NULL;

    KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);
    if (g_DriverEventCount < MAX_EVENT_COUNT) {
        InsertTailList(&g_DriverEventQueue, &node->ListEntry);
        g_DriverEventCount++;

        if (g_PendingDriverIrp != NULL) {
            if (IoSetCancelRoutine(g_PendingDriverIrp, NULL)) {
                irpToComplete = g_PendingDriverIrp;
                g_PendingDriverIrp = NULL;
                RemoveEntryList(&node->ListEntry);
                g_DriverEventCount--;
            }
            else {
                g_PendingDriverIrp = NULL;
            }
        }
    }
    else {
        InterlockedIncrement64(&g_DriverEventDropCount);
        FreeDriverEventNode(node);
        node = NULL;
    }
    KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

    if (irpToComplete != NULL && node != NULL) {
        RtlCopyMemory(irpToComplete->AssociatedIrp.SystemBuffer, &node->EventData, sizeof(DRIVER_EVENT));
        irpToComplete->IoStatus.Information = sizeof(DRIVER_EVENT);
        irpToComplete->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(irpToComplete, IO_NO_INCREMENT);
        FreeDriverEventNode(node);
    }
}

static BOOLEAN IsProtectedTargetProcess(
    _In_ ULONG processId,
    _In_opt_ PEPROCESS process,
    _Out_writes_(displayNameLength) WCHAR* displayName,
    _In_ SIZE_T displayNameLength) {
    if (displayName == NULL || displayNameLength == 0) {
        return FALSE;
    }

    displayName[0] = L'\0';
    if (processId == 0 || processId == 4) {
        CopyWideStringToFixedBuffer(displayName, displayNameLength, L"system");
        return TRUE;
    }

    if (process == NULL) {
        return FALSE;
    }

    PUNICODE_STRING imagePath = NULL;
    if (NT_SUCCESS(QueryProcessImageNameCompat(process, &imagePath)) &&
        imagePath != NULL &&
        imagePath->Buffer != NULL &&
        imagePath->Length > 0) {
        CopyUnicodeFileNameToFixedBuffer(displayName, displayNameLength, imagePath);
        BOOLEAN isProtected = IsProtectedFullImagePath(imagePath);
        ExFreePool(imagePath);
        if (isProtected) {
            return TRUE;
        }

        return FALSE;
    }

    PCHAR imageName = PsGetProcessImageFileName(process);
    if (imageName != NULL && imageName[0] != '\0') {
        CopyAnsiStringToWideBuffer(displayName, displayNameLength, imageName);
        return IsProtectedShortImageName(imageName);
    }

    return FALSE;
}

static NTSTATUS TerminateTargetProcessById(_In_ ULONG processId, _In_ LONG exitStatus) {
    if (processId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(processId), &process);
    if (!NT_SUCCESS(status)) {
        QueueResponseActionEvent(RESPONSE_ACTION_TERMINATE_PROCESS, processId, NULL, status);
        return status;
    }

    WCHAR imageNameBuffer[MAX_RULE_LENGTH] = {};
    if (IsProtectedTargetProcess(processId, process, imageNameBuffer, RTL_NUMBER_OF(imageNameBuffer))) {
        KdPrint(("[PebMonitor] WARN: Rejecting terminate request for protected process. PID=%lu Image=%ws\n",
            processId,
            (imageNameBuffer[0] != L'\0') ? imageNameBuffer : L"<unknown>"));
        ObDereferenceObject(process);
        QueueResponseActionEvent(RESPONSE_ACTION_TERMINATE_PROCESS, processId, imageNameBuffer, STATUS_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    HANDLE processHandle = NULL;
    status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_TERMINATE,
        *PsProcessType,
        KernelMode,
        &processHandle);
    ObDereferenceObject(process);

    if (!NT_SUCCESS(status)) {
        KdPrint(("[PebMonitor] WARN: Failed to open process for terminate. PID=%lu Status=0x%08X\n",
            processId,
            status));
        QueueResponseActionEvent(RESPONSE_ACTION_TERMINATE_PROCESS, processId, imageNameBuffer, status);
        return status;
    }

    status = ZwTerminateProcess(processHandle, exitStatus);
    ZwClose(processHandle);

    KdPrint(("[PebMonitor] INFO: Terminate process request completed. PID=%lu Status=0x%08X ExitStatus=0x%08X\n",
        processId,
        status,
        (ULONG)exitStatus));
    QueueResponseActionEvent(RESPONSE_ACTION_TERMINATE_PROCESS, processId, imageNameBuffer, status);
    return status;
}

static VOID FillDriverRuntimeStatus(_Out_ PDRIVER_RUNTIME_STATUS runtimeStatus) {
    RtlZeroMemory(runtimeStatus, sizeof(DRIVER_RUNTIME_STATUS));
    FILE_PROTECTION_RUNTIME_STATS fileProtectionStats = {};

    runtimeStatus->AbiVersion = PEBMONITOR_ABI_VERSION;
    runtimeStatus->StatusFlags = ReadInterlockedFlags((volatile LONG*)&g_RuntimeStatusFlags);
    runtimeStatus->ProtectionMode = (ULONG)g_ProtectionMode;
    runtimeStatus->PolicyEpoch = ReadInterlockedFlags((volatile LONG*)&g_PolicyEpoch);
    runtimeStatus->LastHeartbeatTime = ReadInterlockedCounter64(&g_LastHeartbeatTime);
    runtimeStatus->ProcessBreakerOpenCount = ReadInterlockedCounter64(&g_ProcessBreakerOpenCount);
    runtimeStatus->LastProcessBreakerOpenTime = ReadInterlockedCounter64(&g_LastProcessBreakerOpenTime);
    runtimeStatus->LastProcessBreakerCloseTime = ReadInterlockedCounter64(&g_LastProcessBreakerCloseTime);

    AcquireSharedResourceLock(&g_RuntimeStatusLock);
    runtimeStatus->ProcessVerdictRequestCount = g_ProcessVerdictRequestCount;
    runtimeStatus->ProcessVerdictTimeoutCount = g_ProcessVerdictTimeoutCount;
    runtimeStatus->ProcessPortConnectCount = g_ProcessPortConnectCount;
    runtimeStatus->ProcessPortDisconnectCount = g_ProcessPortDisconnectCount;
    runtimeStatus->LastProcessPortConnectTime = g_LastProcessPortConnectTime;
    runtimeStatus->LastProcessPortDisconnectTime = g_LastProcessPortDisconnectTime;
    runtimeStatus->LastProcessVerdictTimeoutTime = g_LastProcessVerdictTimeoutTime;
    runtimeStatus->ProcessVerdictTimeoutMs = g_ProcessVerdictTimeoutMs;
    runtimeStatus->ProcessVerdictFailMode = g_ProcessVerdictFailMode;
    runtimeStatus->HeartbeatIntervalMs = g_HeartbeatIntervalMs;
    runtimeStatus->HeartbeatTimeoutMs = g_HeartbeatTimeoutMs;
    runtimeStatus->CaptureParentCommandLine = g_CaptureParentCommandLine;
    RtlStringCchCopyW(runtimeStatus->ConfigVersion, RTL_NUMBER_OF(runtimeStatus->ConfigVersion), g_ActiveConfigVersion);
    RtlStringCchCopyW(runtimeStatus->ProfileName, RTL_NUMBER_OF(runtimeStatus->ProfileName), g_ActiveProfileName);
    RtlStringCchCopyW(runtimeStatus->GeneratedAt, RTL_NUMBER_OF(runtimeStatus->GeneratedAt), g_ActiveGeneratedAt);
    ReleaseSharedResourceLock(&g_RuntimeStatusLock);

    runtimeStatus->RegistryRuleCount = QueryRuleStoreRuleCount(&g_RegistryBlockRuleStore);
    runtimeStatus->RegistryAllowRuleCount = QueryRuleStoreRuleCount(&g_RegistryAllowRuleStore);
    QueryRuleStoreBucketCounts(
        &g_RegistryBlockRuleStore,
        &runtimeStatus->RegistryRuleExactCount,
        &runtimeStatus->RegistryRulePrefixCount,
        &runtimeStatus->RegistryRuleSuffixCount,
        &runtimeStatus->RegistryRuleContainsCount);
    QueryRuleStoreBucketCounts(
        &g_RegistryAllowRuleStore,
        &runtimeStatus->RegistryAllowRuleExactCount,
        &runtimeStatus->RegistryAllowRulePrefixCount,
        &runtimeStatus->RegistryAllowRuleSuffixCount,
        &runtimeStatus->RegistryAllowRuleContainsCount);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);
    runtimeStatus->DriverEventQueueCount = g_DriverEventCount;
    KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

    runtimeStatus->DriverEventDropCount = ReadInterlockedCounter64(&g_DriverEventDropCount);
    runtimeStatus->DriverEventAllocFailCount = ReadInterlockedCounter64(&g_DriverEventAllocFailCount);
    runtimeStatus->FastPathHitCount = ReadInterlockedCounter64(&g_FastPathHitCount);
    runtimeStatus->CacheHitCount = ReadInterlockedCounter64(&g_DecisionCacheHitCount);
    runtimeStatus->CacheMissCount = ReadInterlockedCounter64(&g_DecisionCacheMissCount);
    runtimeStatus->CacheFlushCount = ReadInterlockedCounter64(&g_DecisionCacheFlushCount);
    runtimeStatus->SlowPathCount = ReadInterlockedCounter64(&g_SlowPathCount);

    GetFileProtectionRuntimeStats(&fileProtectionStats);
    runtimeStatus->FileProtectionBlockCount = fileProtectionStats.BlockCount;
    runtimeStatus->FileProtectionCreateBlockCount = fileProtectionStats.CreateBlockCount;
    runtimeStatus->FileProtectionSetInformationBlockCount = fileProtectionStats.SetInformationBlockCount;
    RtlStringCchCopyW(
        runtimeStatus->LastFileProtectionInfoClass,
        RTL_NUMBER_OF(runtimeStatus->LastFileProtectionInfoClass),
        fileProtectionStats.LastInfoClass);
}

VOID CancelPendingDriverIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    IoReleaseCancelSpinLock(Irp->CancelIrql);
    PIRP irpToCancel = (PIRP)InterlockedCompareExchangePointer((PVOID*)&g_PendingDriverIrp, NULL, Irp);
    if (irpToCancel != NULL) {
        irpToCancel->IoStatus.Status = STATUS_CANCELLED;
        irpToCancel->IoStatus.Information = 0;
        IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
    }
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

    switch (ioControlCode) {
    case IOCTL_QUERY_DRIVER_STATUS: {
        if (outBufLength < sizeof(DRIVER_RUNTIME_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PDRIVER_RUNTIME_STATUS runtimeStatus =
            (PDRIVER_RUNTIME_STATUS)Irp->AssociatedIrp.SystemBuffer;
        FillDriverRuntimeStatus(runtimeStatus);
        Irp->IoStatus.Information = sizeof(DRIVER_RUNTIME_STATUS);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_SET_ACTIVE_CONFIG_INFO: {
        if (inBufLength < sizeof(DRIVER_CONFIG_INFO)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PDRIVER_CONFIG_INFO configInfo =
            (PDRIVER_CONFIG_INFO)Irp->AssociatedIrp.SystemBuffer;
        configInfo->ConfigVersion[MAX_RULE_LENGTH - 1] = L'\0';
        configInfo->ProfileName[MAX_RULE_LENGTH - 1] = L'\0';
        configInfo->GeneratedAt[MAX_RULE_LENGTH - 1] = L'\0';

        ULONG timeoutMs = configInfo->ProcessVerdictTimeoutMs;
        if (timeoutMs < PROCESS_VERDICT_TIMEOUT_MS_MIN ||
            timeoutMs > PROCESS_VERDICT_TIMEOUT_MS_MAX) {
            timeoutMs = PROCESS_VERDICT_TIMEOUT_MS_DEFAULT;
        }

        ULONG failMode = configInfo->ProcessVerdictFailMode;
        if (failMode != PROCESS_VERDICT_FAIL_OPEN &&
            failMode != PROCESS_VERDICT_FAIL_CLOSE) {
            failMode = PROCESS_VERDICT_FAIL_OPEN;
        }

        ULONG captureParentCmdline = configInfo->CaptureParentCommandLine;
        if (captureParentCmdline != PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED) {
            captureParentCmdline = PROCESS_PARENT_CMDLINE_CAPTURE_DISABLED;
        }

        AcquireExclusiveResourceLock(&g_RuntimeStatusLock);
        RtlZeroMemory(g_ActiveConfigVersion, sizeof(g_ActiveConfigVersion));
        RtlZeroMemory(g_ActiveProfileName, sizeof(g_ActiveProfileName));
        RtlZeroMemory(g_ActiveGeneratedAt, sizeof(g_ActiveGeneratedAt));
        g_ProcessVerdictTimeoutMs = timeoutMs;
        g_ProcessVerdictFailMode = failMode;
        g_CaptureParentCommandLine = captureParentCmdline;
        RtlStringCchCopyW(g_ActiveConfigVersion, RTL_NUMBER_OF(g_ActiveConfigVersion), configInfo->ConfigVersion);
        RtlStringCchCopyW(g_ActiveProfileName, RTL_NUMBER_OF(g_ActiveProfileName), configInfo->ProfileName);
        RtlStringCchCopyW(g_ActiveGeneratedAt, RTL_NUMBER_OF(g_ActiveGeneratedAt), configInfo->GeneratedAt);
        ReleaseExclusiveResourceLock(&g_RuntimeStatusLock);

        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_HIPS_HEARTBEAT: {
        RecordProcessHeartbeatEvent();
        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_EDR_TERMINATE_PROCESS: {
        if (inBufLength < sizeof(EDR_TERMINATE_PROCESS_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PEDR_TERMINATE_PROCESS_REQUEST request =
            (PEDR_TERMINATE_PROCESS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        status = TerminateTargetProcessById(request->ProcessId, request->ExitStatus);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_GET_DRIVER_EVENT: {
        if (outBufLength < sizeof(DRIVER_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DriverQueueLock, &oldIrql);

        if (!IsListEmpty(&g_DriverEventQueue)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_DriverEventQueue);
            g_DriverEventCount--;
            PDRIVER_EVENT_NODE node = CONTAINING_RECORD(entry, DRIVER_EVENT_NODE, ListEntry);
            DRIVER_EVENT tempEvent = node->EventData;
            KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

            FreeDriverEventNode(node);
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &tempEvent, sizeof(DRIVER_EVENT));
            Irp->IoStatus.Information = sizeof(DRIVER_EVENT);
            status = STATUS_SUCCESS;
        }
        else {
            KeReleaseSpinLock(&g_DriverQueueLock, oldIrql);

            IoMarkIrpPending(Irp);
            PIRP oldIrp = (PIRP)InterlockedExchangePointer((PVOID*)&g_PendingDriverIrp, Irp);

            if (oldIrp != NULL) {
                if (IoSetCancelRoutine(oldIrp, NULL) != NULL) {
                    oldIrp->IoStatus.Status = STATUS_CANCELLED;
                    oldIrp->IoStatus.Information = 0;
                    IoCompleteRequest(oldIrp, IO_NO_INCREMENT);
                }
            }

            IoSetCancelRoutine(Irp, CancelPendingDriverIrp);
            if (Irp->Cancel) {
                if (IoSetCancelRoutine(Irp, NULL) != NULL) {
                    PIRP irpToCancel = (PIRP)InterlockedCompareExchangePointer((PVOID*)&g_PendingDriverIrp, NULL, Irp);
                    if (irpToCancel != NULL) {
                        irpToCancel->IoStatus.Status = STATUS_CANCELLED;
                        irpToCancel->IoStatus.Information = 0;
                        IoCompleteRequest(irpToCancel, IO_NO_INCREMENT);
                    }
                }
            }
            return STATUS_PENDING;
        }
        break;
    }

    case IOCTL_ADD_REGISTRY_RULE: {
        if (inBufLength < sizeof(REGISTRY_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREGISTRY_RULE rule = (PREGISTRY_RULE)Irp->AssociatedIrp.SystemBuffer;
        REGISTRY_RULE sanitizedRule = *rule;
        SanitizeRegistryRule(&sanitizedRule);

        status = ApplyRegistryRuleUpdate(
            &g_RegistryBlockRuleStore,
            &sanitizedRule,
            FALSE,
            NULL);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_REGISTRY_RULES: {
        status = ApplyRegistryRuleUpdate(
            &g_RegistryBlockRuleStore,
            NULL,
            TRUE,
            NULL);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_REPLACE_REGISTRY_RULES: {
        PREGISTRY_RULE sanitizedRules = NULL;
        ULONG ruleCount = 0;

        status = CaptureSanitizedRegistryRuleBatch(
            Irp->AssociatedIrp.SystemBuffer,
            inBufLength,
            &sanitizedRules,
            &ruleCount);
        if (NT_SUCCESS(status)) {
            status = ReplaceRegistryRuleStore(
                &g_RegistryBlockRuleStore,
                sanitizedRules,
                ruleCount,
                NULL);
        }

        FreeSanitizedRegistryRuleBatch(sanitizedRules);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_ADD_REGISTRY_ALLOW_RULE: {
        if (inBufLength < sizeof(REGISTRY_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREGISTRY_RULE rule = (PREGISTRY_RULE)Irp->AssociatedIrp.SystemBuffer;
        REGISTRY_RULE sanitizedRule = *rule;
        SanitizeRegistryRule(&sanitizedRule);

        status = ApplyRegistryRuleUpdate(
            &g_RegistryAllowRuleStore,
            &sanitizedRule,
            FALSE,
            NULL);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_CLEAR_REGISTRY_ALLOW_RULES: {
        status = ApplyRegistryRuleUpdate(
            &g_RegistryAllowRuleStore,
            NULL,
            TRUE,
            NULL);
        Irp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_REPLACE_REGISTRY_ALLOW_RULES: {
        PREGISTRY_RULE sanitizedRules = NULL;
        ULONG ruleCount = 0;

        status = CaptureSanitizedRegistryRuleBatch(
            Irp->AssociatedIrp.SystemBuffer,
            inBufLength,
            &sanitizedRules,
            &ruleCount);
        if (NT_SUCCESS(status)) {
            status = ReplaceRegistryRuleStore(
                &g_RegistryAllowRuleStore,
                sanitizedRules,
                ruleCount,
                NULL);
        }

        FreeSanitizedRegistryRuleBatch(sanitizedRules);
        Irp->IoStatus.Information = 0;
        break;
    }
    }

    if (status != STATUS_PENDING) {
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    return status;
}

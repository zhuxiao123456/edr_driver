param(
    [string]$RepoRoot = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sharedHeaderPath = Join-Path $RepoRoot 'Common\PebMonitorShared.h'
$ioctlDispatchPath = Join-Path $RepoRoot 'IoctlDispatch.cpp'
$fileProtectionHeaderPath = Join-Path $RepoRoot 'FileProtection.h'
$fileProtectionPath = Join-Path $RepoRoot 'FileProtection.cpp'

if (-not (Test-Path $sharedHeaderPath)) {
    throw "Shared header not found: $sharedHeaderPath"
}

if (-not (Test-Path $ioctlDispatchPath)) {
    throw "IoctlDispatch.cpp not found: $ioctlDispatchPath"
}

foreach ($path in @($fileProtectionHeaderPath, $fileProtectionPath)) {
    if (-not (Test-Path $path)) {
        throw "Required file not found: $path"
    }
}

$sharedHeaderText = Get-Content $sharedHeaderPath -Raw
$ioctlDispatchText = Get-Content $ioctlDispatchPath -Raw
$fileProtectionHeaderText = Get-Content $fileProtectionHeaderPath -Raw
$fileProtectionText = Get-Content $fileProtectionPath -Raw

if ($sharedHeaderText -notmatch 'PEBMONITOR_ABI_VERSION') {
    throw 'PEBMONITOR_ABI_VERSION is missing from Common\PebMonitorShared.h.'
}

if ($sharedHeaderText -notmatch 'typedef struct _DRIVER_RUNTIME_STATUS\s*\{\s*ULONG\s+AbiVersion;') {
    throw 'DRIVER_RUNTIME_STATUS must start with AbiVersion.'
}

$requiredRuntimeStatusFields = @(
    'PolicyEpoch',
    'RegistryRuleExactCount',
    'RegistryRulePrefixCount',
    'RegistryRuleSuffixCount',
    'RegistryRuleContainsCount',
    'RegistryAllowRuleExactCount',
    'RegistryAllowRulePrefixCount',
    'RegistryAllowRuleSuffixCount',
    'RegistryAllowRuleContainsCount',
    'FastPathHitCount',
    'CacheHitCount',
    'CacheMissCount',
    'CacheFlushCount',
    'SlowPathCount',
    'FileProtectionBlockCount',
    'FileProtectionCreateBlockCount',
    'FileProtectionSetInformationBlockCount',
    'LastFileProtectionInfoClass'
)

foreach ($field in $requiredRuntimeStatusFields) {
    if ($sharedHeaderText -notmatch ('\b' + [regex]::Escape($field) + '\b')) {
        throw "DRIVER_RUNTIME_STATUS is missing field: $field"
    }
}

if ($sharedHeaderText -notmatch 'FIELD_OFFSET\s*\(\s*DRIVER_RUNTIME_STATUS\s*,\s*AbiVersion\s*\)\s*==\s*0') {
    throw 'DRIVER_RUNTIME_STATUS must assert AbiVersion offset 0.'
}

if ($ioctlDispatchText -notmatch 'runtimeStatus->AbiVersion\s*=\s*PEBMONITOR_ABI_VERSION') {
    throw 'FillDriverRuntimeStatus must set AbiVersion.'
}

if ($ioctlDispatchText -notmatch 'runtimeStatus->PolicyEpoch') {
    throw 'FillDriverRuntimeStatus must populate PolicyEpoch.'
}

if ($fileProtectionHeaderText -notmatch 'typedef struct _FILE_PROTECTION_RUNTIME_STATS') {
    throw 'FileProtection.h must declare FILE_PROTECTION_RUNTIME_STATS.'
}

if ($fileProtectionHeaderText -notmatch 'GetFileProtectionRuntimeStats') {
    throw 'FileProtection.h must expose GetFileProtectionRuntimeStats.'
}

$requiredIoctlAssignments = @(
    'runtimeStatus->RegistryRuleExactCount',
    'runtimeStatus->RegistryRulePrefixCount',
    'runtimeStatus->RegistryRuleSuffixCount',
    'runtimeStatus->RegistryRuleContainsCount',
    'runtimeStatus->RegistryAllowRuleExactCount',
    'runtimeStatus->RegistryAllowRulePrefixCount',
    'runtimeStatus->RegistryAllowRuleSuffixCount',
    'runtimeStatus->RegistryAllowRuleContainsCount',
    'runtimeStatus->FileProtectionBlockCount',
    'runtimeStatus->FileProtectionCreateBlockCount',
    'runtimeStatus->FileProtectionSetInformationBlockCount'
)

foreach ($assignment in $requiredIoctlAssignments) {
    if ($ioctlDispatchText -notmatch [regex]::Escape($assignment)) {
        throw "FillDriverRuntimeStatus must populate $assignment."
    }
}

if ($ioctlDispatchText -notmatch 'GetFileProtectionRuntimeStats') {
    throw 'IoctlDispatch.cpp must query file-protection runtime stats.'
}

if ($ioctlDispatchText -notmatch 'runtimeStatus->LastFileProtectionInfoClass') {
    throw 'FillDriverRuntimeStatus must populate LastFileProtectionInfoClass.'
}

if ($fileProtectionText -notmatch 'InterlockedIncrement64\s*\(&g_FileProtectionBlockCount\)') {
    throw 'FileProtection.cpp must increment g_FileProtectionBlockCount when blocking requests.'
}

if ($fileProtectionText -notmatch 'InterlockedIncrement64\s*\(&g_FileProtectionCreateBlockCount\)') {
    throw 'FileProtection.cpp must increment g_FileProtectionCreateBlockCount for blocked create requests.'
}

if ($fileProtectionText -notmatch 'InterlockedIncrement64\s*\(&g_FileProtectionSetInformationBlockCount\)') {
    throw 'FileProtection.cpp must increment g_FileProtectionSetInformationBlockCount for blocked set-information requests.'
}

Write-Host '[+] Driver ABI/runtime status contract checks passed.'

#Requires -Version 7.0

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [string] $SdkRoot = (Join-Path $PSScriptRoot '..\..\..\sdk'),
    [string] $ApigenPath = (Join-Path $PSScriptRoot 'apigen.exe')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$root = Get-Item -LiteralPath $SdkRoot
if (-not $root.PSIsContainer) {
    throw "SDK root is not a directory: $SdkRoot"
}
$generator = Get-Item -LiteralPath $ApigenPath
if ($generator.PSIsContainer) {
    throw "apigen executable is not a file: $ApigenPath"
}

$modules = @(Get-ChildItem -LiteralPath $root.FullName -Filter 'go.mod' -File -Recurse |
    Sort-Object -Property FullName)
if ($modules.Count -eq 0) {
    throw "No Go modules found under $($root.FullName)"
}

$failedModules = [System.Collections.Generic.List[string]]::new()
Write-Output "Generating API reports for $($modules.Count) modules under $($root.FullName)"

try {
    for ($i = 0; $i -lt $modules.Count; $i++) {
        $moduleDirectory = $modules[$i].DirectoryName
        $reportPath = Join-Path $moduleDirectory 'api.md'
        Write-Progress -Activity 'Generating API reports' -Status $moduleDirectory `
            -PercentComplete (($i * 100) / $modules.Count)

        & $generator.FullName $moduleDirectory -o $reportPath
        $generationExitCode = $LASTEXITCODE
        $reportExists = Test-Path -LiteralPath $reportPath -PathType Leaf
        if ($generationExitCode -ne 0 -or -not $reportExists) {
            $failedModules.Add($moduleDirectory)
            if ($generationExitCode -eq 0) {
                Write-Warning "apigen returned success but did not create $reportPath"
            }
        }
    }
}
finally {
    Write-Progress -Activity 'Generating API reports' -Completed
}

if ($failedModules.Count -gt 0) {
    Write-Output "Failed to generate api.md for $($failedModules.Count) of $($modules.Count) modules:"
    $failedModules | Write-Output
    exit 1
}

Write-Output "Successfully generated api.md for all $($modules.Count) modules."
exit 0

<#PSScriptInfo

.VERSION 0.0.0
.GUID dcedf485-42a4-4ed2-a96a-4ad1f344e1a0
.AUTHOR DevOps Team
.COMPANYNAME SOTI Inc.
.COPYRIGHT Copyright (C) SOTI Inc.
.TAGS
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS Soti.Utilities:[1.0.0,1.9999.9999], Soti.Utilities.IO:[1.0.0,1.9999.9999], Expand-ZipFile:[1.1.0,1.9999.9999]
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.DESCRIPTION N/A

#>

#Requires -Version 5

using namespace System
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace System.IO

[CmdletBinding(PositionalBinding = $false)]
param
(
    [Parameter(Position = 0)]
    [hashtable] $CommonArguments,

    [Parameter(Position = 1)]
    [psobject] $Arguments
)
begin
{
    $Script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    Microsoft.PowerShell.Core\Set-StrictMode -Version 1

    . 'Soti.Utilities.ps1'
    . 'Soti.Utilities.IO.ps1'

    if ([string]::IsNullOrWhiteSpace($Arguments.SourceArchiveFilePath))
    {
        throw [ArgumentException]::new("The templated path of archive file is required.", 'Arguments.SourceArchiveFilePath')
    }

    if ([string]::IsNullOrWhiteSpace($Arguments.FileNameWildcard))
    {
        throw [ArgumentException]::new("The wildcard of the Agent Simulator file name is required.", 'Arguments.FileNameWildcard')
    }

    if ([string]::IsNullOrWhiteSpace($Arguments.DestinationDirectory))
    {
        throw [ArgumentException]::new("The templated path to the destination directory is required.", 'Arguments.DestinationDirectory')
    }
}
process
{
    [string] $resolvedSourceArchiveFilePath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.SourceArchiveFilePath,
        [RelativePathRequirements]::MustBelong -bor [RelativePathRequirements]::MustExist)

    [string] $fileNameWildcard = $Arguments.FileNameWildcard

    [string] $resolvedDestinationDirectory = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.DestinationDirectory,
        [RelativePathRequirements]::MustBelong)

    [string] $intermediateDirectory = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        "`$Root:tmp_agentSimulator_$([guid]::NewGuid().ToString('N'))",
        [RelativePathRequirements]::MustBelong)

    Write-Host "Extracting files from ""$resolvedSourceArchiveFilePath"" to the intermediate directory ""$intermediateDirectory""."
    Expand-ZipFile -SourcePath $resolvedSourceArchiveFilePath -DestinationPath $intermediateDirectory -Clean

    [string[]] $foundFilePaths = @(Get-ChildItem -Path ([Path]::Combine($intermediateDirectory, $fileNameWildcard)) -Recurse -Force -File).FullName
    if ((Test-NullOrEmptyArray $foundFilePaths) -or $foundFilePaths.Count -ne 1)
    {
        throw "There must be exactly one Agent Simulator file matching the pattern ""$fileNameWildcard"", but found $($foundFilePaths.Count)."
    }

    [string] $foundFilePath = $foundFilePaths[0]
    Write-Host "Found Agent Simulator binary at ""$foundFilePath""."

    [string] $sourceDirectory = [Path]::GetDirectoryName($foundFilePath)

    Ensure-DirectoryExists -LiteralPath $resolvedDestinationDirectory -Clean
    Move-Item -Path "$sourceDirectory\*" -Destination $resolvedDestinationDirectory -Force -Verbose

    Write-Host "Deleting the intermediate directory ""$intermediateDirectory""."
    Remove-Item -Recurse -Force -LiteralPath $intermediateDirectory
}
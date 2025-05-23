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
.REQUIREDSCRIPTS Soti.Utilities:[1.0.0,1.9999.9999], Soti.Utilities.IO:[1.0.0,1.9999.9999], Execute-ExternalCommand:[1.0.0,1.9999.9999]
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.DESCRIPTION N/A

#>

#Requires -Version 5

using namespace System
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
    $script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    Set-StrictMode -Version 1

    . 'Soti.Utilities.ps1'
    . 'Soti.Utilities.IO.ps1'

    if ([string]::IsNullOrWhiteSpace($Arguments.DownloadDirectory))
    {
        throw [ArgumentException]::new("Templated path to the chocolatey package download directory is required.", '$Arguments.DownloadDirectory')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.DefaultSource))
    {
        throw [ArgumentException]::new("The URL to the default Chocolatey feed is required.", '$Arguments.DefaultSource')
    }
    if (Test-NullOrEmptyArray -Value $Arguments.Packages)
    {
        throw [ArgumentException]::new("MobiControl API Client password is required.", '$Arguments.Packages')
    }

    [string] $packageDownloadPath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.DownloadDirectory,
        [RelativePathRequirements]::MustBelong)

    Ensure-DirectoryExists -LiteralPath $packageDownloadPath -Clean
    [string] $packageListFilePath = [Path]::Combine($packageDownloadPath, 'packages.chocolatey.json')
}
process
{
    Write-Host ''
    Write-Host '* Downloading Chocolatey packages...'
    Write-Host "Default source: ""$($Arguments.DefaultSource)""."

    [hashtable[]] $packageDatas = @()
    foreach ($package in $Arguments.Packages)
    {
        [ValidateNotNullOrEmpty()] [string] $packageId = $package.Id
        [ValidateNotNullOrEmpty()] [string] $packageVersion = $package.Version

        [string] $feedUrl = $package.Source
        if ([string]::IsNullOrWhiteSpace($feedUrl))
        {
            $feedUrl = $Arguments.DefaultSource
        }

        [string[]] $cliArguments = `
        @(
            'install',
            """$packageId""",
            '-Version',
            """$packageVersion""",
            '-Source',
            """$feedUrl""",
            '-NonInteractive',
            '-Prerelease',
            '-OutputDirectory',
            """$packageDownloadPath"""
        )

        Execute-ExternalCommand `
            -Verbose `
            -Title "Installing package ""$packageId"" version ""$packageVersion""" `
            -Command nuget.exe `
            -CommandArguments $cliArguments

        [string] $expandedPackageName = "$packageId.$packageVersion"

        [string] $packageFilePath = [Path]::Combine($packageDownloadPath, $expandedPackageName, "$expandedPackageName.nupkg")
        Assert-FileExists -LiteralPath $packageFilePath
        Move-Item -LiteralPath $packageFilePath -Destination $packageDownloadPath -Force

        $packageDatas += @{ id = $packageId; version = $packageVersion }
    }

    Get-ChildItem -LiteralPath $packageDownloadPath -Directory | Remove-Item -Force -Recurse

    Set-Content -LiteralPath $packageListFilePath -Value $($packageDatas | ConvertTo-Json) -Encoding UTF8 | Out-Null

    Write-Host ''
    Write-Host '* Downloading Chocolatey packages - DONE.'
}
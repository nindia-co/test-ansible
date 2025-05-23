<#PSScriptInfo

.VERSION 0.0.0
.GUID 109455f1-f035-4873-9160-074e2e67ce02
.AUTHOR DevOps Team
.COMPANYNAME SOTI Inc.
.COPYRIGHT Copyright (C) SOTI Inc.
.TAGS
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS Soti.Utilities:[1.0.0,1.9999.9999], Soti.Utilities.IO:[1.0.0,1.9999.9999]
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.DESCRIPTION N/A

#>

#Requires -Version 5

using namespace System
using namespace System.Diagnostics
using namespace System.IO

[CmdletBinding(PositionalBinding = $false)]
param (
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

    if ([string]::IsNullOrWhiteSpace($Arguments.AccessKey))
    {
        throw [ArgumentException]::new("AWS API access key is required.", '$Arguments.AccessKey')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.SecretKey))
    {
        throw [ArgumentException]::new("AWS API secret key is required.", '$Arguments.SecretKey')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.Region))
    {
        throw [ArgumentException]::new("The name of AWS default region is required.", '$Arguments.Region')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.Output))
    {
        throw [ArgumentException]::new("AWS CLI output type is required.", '$Arguments.Output')
    }

    [string] $awsProfileDirectory = [Path]::Combine($env:USERPROFILE, '.aws')

    Ensure-DirectoryExists -LiteralPath $awsProfileDirectory -Clean
}
process
{
    Write-Host ''
    Write-Host '* Configuring AWS default profile.'
    Write-Host "Region = ""$($Arguments.Region)"""
    Write-Host "Output = ""$($Arguments.Output)"""

    [string] $credential = @"
[default]
aws_access_key_id = $($Arguments.AccessKey)
aws_secret_access_key = $($Arguments.SecretKey)

"@

    [string] $credentialFilePath = [Path]::Combine($awsProfileDirectory, 'credentials')
    Set-Content -LiteralPath $credentialFilePath -Value $credential -Force

    [string] $config = @"
[default]
region = $($Arguments.Region)
output = $($Arguments.Output)

"@
    [string] $configFilePath = [Path]::Combine($awsProfileDirectory, 'config')
    Set-Content -LiteralPath $configFilePath -Value $config -Force

    Write-Host ''
    Write-Host '* Configuring AWS default profile - DONE.'
}
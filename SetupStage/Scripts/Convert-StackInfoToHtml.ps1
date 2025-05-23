<#PSScriptInfo

.VERSION 0.0.0
.GUID 33cce575-c5b6-4dc1-854f-c47b17cb1feb
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
using namespace System.Management.Automation
using namespace System.Management.Automation.Runspaces

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

    [string] $commonScriptPath = "$PSScriptRoot\..\..\.Common\Scripts\Common.ps1"
    . $commonScriptPath

    if ([string]::IsNullOrWhiteSpace($Arguments.StackInfoFilePath))
    {
        throw [ArgumentException]::new(
            'The templated path of the output file of stack information is required.',
            'Arguments.StackInfoFilePath')
    }

    [string] $cssStyle = @'
        *
        {
            box-sizing: border-box;
        }

        body
        {
            color: black;
            font-family: Verdana, Tahoma, Arial;
            font-size: 12px;
            font-weight: normal;
            font-style: normal;
            text-decoration: none;
            margin: 0;
        }

        table
        {
            border-collapse: collapse;
            width: 100%;
        }

        td, th
        {
            padding: 3px 5px;
            border: 1px solid gray;
            vertical-align: top;
            white-space: nowrap;
        }

        td
        {
            font-family: monospace;
            white-space: pre;
        }

        th
        {
            color: #ffffff;
            background-color: #4060C0;
            font-size: 14px;
            font-weight: bold;
        }

        tr:nth-child(odd)
        {
            background-color: #ddeeff;
        }
'@

    [string[]] $htmlHead = `
    @(
        "<style type=""text/css"">$cssStyle</style>",
        '<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>'
    )
}
process
{
    [string] $resolvedStackInfoFilePath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.StackInfoFilePath,
        [RelativePathRequirements]::MustBelong -bor [RelativePathRequirements]::MustExist)

    [psobject] $stackInfo = $resolvedStackInfoFilePath | Get-StackInfo

    [string] $htmlStackInfoFilePath = [Path]::ChangeExtension($resolvedStackInfoFilePath, '.html')

    $stackInfo.PSObject.Properties `
        | Sort-Object -Property Name `
        | ConvertTo-Html -Head $htmlHead -Property @('Name', 'Value') `
        | Set-Content -Encoding UTF8 -Force -LiteralPath $htmlstackInfoFilePath

    $stackInfo | Print-StackInfo
}
<#PSScriptInfo

.VERSION 0.0.0
.GUID 865021f5-726a-4b51-90ac-f012def55874
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
    $Script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    Microsoft.PowerShell.Core\Set-StrictMode -Version 1

    . 'Soti.Utilities.ps1'
    . 'Soti.Utilities.IO.ps1'

    if ([string]::IsNullOrWhiteSpace($Arguments.SourceTemplateFile))
    {
        throw [ArgumentException]::new("The templated path of CF template file is required.", 'Arguments.SourceTemplateFile')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.GeneratedTemplateFilePath))
    {
        throw [ArgumentException]::new("The templated path of the generated CloudFormation template file is required.", 'Arguments.GeneratedTemplateFilePath')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.Bucket))
    {
        throw [ArgumentException]::new("The name of the S3 bucket to upload the CloudFormation templates to is required.", 'Arguments.Bucket')
    }
}
process
{
    [string] $resolvedSourceTemplateFile = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.SourceTemplateFile,
        [RelativePathRequirements]::MustBelong -bor [RelativePathRequirements]::MustExist)

    [string] $resolvedGeneratedTemplateFilePath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.GeneratedTemplateFilePath,
        [RelativePathRequirements]::MustBelong)

    Ensure-DirectoryExists -LiteralPath ([Path]::GetDirectoryName($resolvedGeneratedTemplateFilePath))

    [string] $bucket = $Arguments.Bucket

    [string[]] $commandArguments = `
    @(
        'cloudformation',
        'package'
        '--template-file',
        """$resolvedSourceTemplateFile""",
        '--s3-bucket',
        """$bucket""",
        '--output-template-file',
        """$resolvedGeneratedTemplateFilePath"""
    )

    Execute-ExternalCommand `
        -Verbose `
        -Title 'Generate and deploy nested stack templates' `
        -Command "$($env:ProgramFiles)\Amazon\AWSCLI\aws.exe" `
        -CommandArguments $commandArguments
}
<#PSScriptInfo

.VERSION 0.0.0
.GUID b6e9e28c-001c-48f4-8d04-47cba00c8c4e
.AUTHOR DevOps Team
.COMPANYNAME SOTI Inc.
.COPYRIGHT Copyright (C) SOTI Inc.
.TAGS
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS Soti.Utilities:[1.0.0,1.9999.9999], Soti.Utilities.IO:[1.0.0,1.9999.9999], Soti.Utilities.PowerShellGet:[1.0.0,1.9999.9999]
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.DESCRIPTION N/A

#>

#Requires -Version 5

using namespace System
using namespace System.Diagnostics
using namespace System.IO
using namespace System.Linq

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
    . 'Soti.Utilities.PowerShellGet.ps1'

    class VersionRange
    {
        hidden static $AnyVersionMinimumVersion = [version]::new(0, 0, 0)
        hidden static $AnyVersionMaximumVersion = [version]::new([int]::MaxValue, [int]::MaxValue, [int]::MaxValue)

        [version] $MinimumVersion
        [version] $MaximumVersion

        VersionRange()
        {
            $this.MinimumVersion = [VersionRange]::AnyVersionMinimumVersion
            $this.MaximumVersion = [VersionRange]::AnyVersionMaximumVersion
        }

        VersionRange([version] $minimumVersion, [version] $maximumVersion)
        {
            if ([object]::ReferenceEquals($minimumVersion, $null))
            {
                throw [ArgumentNullException]::new('minimumVersion')
            }
            if ([object]::ReferenceEquals($maximumVersion, $null))
            {
                throw [ArgumentNullException]::new('maximumVersion')
            }
            if ($maximumVersion -lt $minimumVersion)
            {
                throw [ArgumentOutOfRangeException]::new(
                    'maximumVersion',
                    $maximumVersion,
                    "Maximum version ($maximumVersion) cannot be less than minimum version ($minimumVersion).")
            }

            $this.MinimumVersion = $minimumVersion
            $this.MaximumVersion = $maximumVersion
        }

        [string] ToString()
        {
            return "[$($this.MinimumVersion); $($this.MaximumVersion)]"
        }

        [bool] IsAnyVersion()
        {
            return $this.MinimumVersion -eq [VersionRange]::AnyVersionMinimumVersion `
                -and $this.MaximumVersion -eq [VersionRange]::AnyVersionMaximumVersion
        }

        [VersionRange] GetIntersectionWith([VersionRange] $other)
        {
            if ([object]::ReferenceEquals($other, $null))
            {
                throw [ArgumentNullException]::new('other')
            }

            [version] $newMinimumVersion = [Enumerable]::Max([version[]]@($this.MinimumVersion, $other.MinimumVersion))
            [version] $newMaximumVersion = [Enumerable]::Min([version[]]@($this.MaximumVersion, $other.MaximumVersion))

            if ($newMinimumVersion -gt $newMaximumVersion)
            {
                return $null
            }

            return [VersionRange]::new($newMinimumVersion, $newMaximumVersion)
        }
    }

    function Convert-ScriptReference
    {
        [CmdletBinding(PositionalBinding = $false)]
        [OutputType([hashtable])]
        param
        (
            [Parameter(Position = 0, ValueFromPipeline = $true)]
            [hashtable] $ScriptReference
        )
        begin
        {
            [string[]] $properties = @('MinimumVersion', 'MaximumVersion')
        }
        process
        {
            if ([object]::ReferenceEquals($ScriptReference, $null))
            {
                return $null
            }

            [ValidateNotNullOrEmpty()] [string] $name = $ScriptReference.Name

            [hashtable] $result = @{ Name = $name }

            foreach ($property in $properties)
            {
                [string] $value = $ScriptReference[$property]
                if (![string]::IsNullOrEmpty($value))
                {
                    $result[$property] = [version]::Parse($value)
                }
            }

            [string] $requiredVersionValue = $ScriptReference['RequiredVersion']
            if (![string]::IsNullOrEmpty($requiredVersionValue))
            {
                [version] $requiredVersion = [version]::Parse($requiredVersionValue)
                $result['MinimumVersion'] = $requiredVersion
                $result['MaximumVersion'] = $requiredVersion
            }

            return $result
        }
    }

    function Get-ScriptReferenceVersionRange
    {
        [CmdletBinding(PositionalBinding = $false)]
        [OutputType([VersionRange])]
        param
        (
            [Parameter(Position = 0, ValueFromPipeline = $true)]
            [ValidateNotNull()]
            [hashtable] $ScriptReference
        )
        process
        {
            if ([object]::ReferenceEquals($ScriptReference, $null))
            {
                throw [ArgumentNullException]::new('ScriptReference')
            }

            [VersionRange] $result = [VersionRange]::new()

            if ($ScriptReference.MinimumVersion -ne $null -and $ScriptReference.MinimumVersion -is [version])
            {
                $result.MinimumVersion = $ScriptReference.MinimumVersion
            }

            if ($ScriptReference.MaximumVersion -ne $null -and $ScriptReference.MaximumVersion -is [version])
            {
                $result.MaximumVersion = $ScriptReference.MaximumVersion
            }

            # if ($ScriptReference.RequiredVersion -ne $null -and $ScriptReference.RequiredVersion -is [version])
            # {
            #     $result.MinimumVersion = $ScriptReference.RequiredVersion
            #     $result.MaximumVersion = $ScriptReference.RequiredVersion
            # }

            return $result
        }
    }

    function Add-CompatibleVersion
    {
        [CmdletBinding(PositionalBinding = $false)]
        param
        (
            [Parameter()]
            [ValidateNotNull()]
            [hashtable] $ScriptReferences = $(throw [ArgumentNullException]::new('ScriptReferences')),

            [Parameter()]
            [ValidateNotNull()]
            [hashtable] $NewReference = $(throw [ArgumentNullException]::new('NewReference'))
        )
        process
        {
            [ValidateNotNullOrEmpty()] [string] $name = $NewReference.Name

            [hashtable] $existingReference = $ScriptReferences[$name]
            if ([object]::ReferenceEquals($existingReference, $null))
            {
                $ScriptReferences[$name] = $NewReference
                return
            }

            [VersionRange] $existingRange = $existingReference | Get-ScriptReferenceVersionRange
            [VersionRange] $newRange = $NewReference | Get-ScriptReferenceVersionRange

            [VersionRange] $adjustedRange = $existingRange.GetIntersectionWith($newRange)
            if ([object]::ReferenceEquals($adjustedRange, $null))
            {
                throw "Found incompatible references to the dependency script ""$name"": $existingRange and $newRange."
            }

            if (!$adjustedRange.IsAnyVersion())
            {
                $existingReference.MinimumVersion = $adjustedRange.MinimumVersion
                $existingReference.MaximumVersion = $adjustedRange.MaximumVersion
            }
        }
    }
}
process
{
    if ([string]::IsNullOrWhiteSpace($Arguments.Source))
    {
        throw [ArgumentException]::new("Templated path to the source directory is required.", 'Arguments.Source')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.Destination))
    {
        throw [ArgumentException]::new("Templated path to the destination directory is required.", 'Arguments.Destination')
    }

    [string] $resolvedSource = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.Source,
        [RelativePathRequirements]::MustBelong)

    [string] $resolvedDestination = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.Destination,
        [RelativePathRequirements]::MustBelong)

    Ensure-DirectoryExists -LiteralPath $resolvedDestination

    Write-Host ''
    Write-Host "Source: ""$resolvedSource"""
    Write-Host "Destination: ""$resolvedDestination"""
    Write-Host ''

    [hashtable] $scriptReferences = @{}

    if (!(Test-NullOrEmptyArray -Value $Arguments.ExtraScripts))
    {
        foreach ($script in $Arguments.ExtraScripts)
        {
            [ValidateNotNullOrEmpty()] [string] $name = $script.Name
            [ValidateNotNullOrEmpty()] [string] $version = $script.Version

            [hashtable] $parameters = @{ Name = $name; RequiredVersion = $version }
            Add-CompatibleVersion -ScriptReferences $scriptReferences -NewReference $parameters
        }
    }

    [string[]] $scriptFilePaths = @(Get-ChildItem -LiteralPath $resolvedSource -Filter '*.ps1' -Recurse -File).FullName
    foreach ($scriptFilePath in $scriptFilePaths)
    {
        Write-Host ''
        Write-Host "Processing metadata of the script ""$scriptFilePath""."

        [psobject] $scriptFileInfo = `
            try
            {
                Test-ScriptFileInfo -LiteralPath $scriptFilePath -ErrorAction Ignore
            }
            catch
            {
                if ($_.FullyQualifiedErrorId -ine 'MissingPSScriptInfo,Test-ScriptFileInfo')
                {
                    throw
                }

                $null
            }

        if ([object]::ReferenceEquals($scriptFileInfo, $null))
        {
            continue;
        }

        [string[]] $requiredScripts = $scriptFileInfo.RequiredScripts
        Write-Host "    Found $($requiredScripts.Count) dependency script(s)."
        foreach ($requiredScript in $requiredScripts)
        {
            [hashtable] $parsedScriptReference = Parse-PowerShellGetScriptReference -ScriptReference $requiredScript | Convert-ScriptReference
            Add-CompatibleVersion -ScriptReferences $scriptReferences -NewReference $parsedScriptReference
        }
    }

    Write-Host ''
    foreach ($entry in $scriptReferences.GetEnumerator())
    {
        [hashtable] $scriptReference = $entry.Value

        Write-Host ''
        Write-Host "Saving dependency script:"
        Write-Host ($scriptReference | Out-String)

        Save-Script -Force -AcceptLicense -LiteralPath $resolvedDestination @scriptReference
    }
}
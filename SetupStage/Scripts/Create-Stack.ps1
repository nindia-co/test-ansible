<#PSScriptInfo

.VERSION 0.0.0
.GUID d0e9194d-9fd3-4a41-8006-ce8ccf60d8fb
.AUTHOR DevOps Team
.COMPANYNAME SOTI Inc.
.COPYRIGHT Copyright (C) SOTI Inc.
.TAGS
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
    Soti.Utilities.Cryptography:[1.1.0,1.9999.9999]
    Soti.Utilities.MobiControl:[1.0.0,1.9999.9999]
    Invoke-TerraformStack:[1.0.0,1.9999.9999]
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.DESCRIPTION N/A

#>

#Requires -Version 5

using namespace System
using namespace System.Data
using namespace System.Data.SqlClient
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

    . 'Soti.Utilities.Cryptography.ps1'
    . 'Soti.Utilities.MobiControl.ps1'

    . "$PSScriptRoot\..\..\.Common\Scripts\Common.ps1"

    if ([string]::IsNullOrWhiteSpace($Arguments.InfrastructureType))
    {
        throw [ArgumentException]::new('The type of the infrastructure used cannot be blank.', 'Arguments.InfrastructureType')
    }

    switch ($Arguments.InfrastructureType) 
    {
        'AWS' 
        {  
            if ([string]::IsNullOrWhiteSpace($Arguments.Region))
            {
                throw [ArgumentException]::new('The name of AWS region cannot be blank.', 'Arguments.Region')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.AccessKey))
            {
                throw [ArgumentException]::new('AWS IAM user access key cannot be blank.', 'Arguments.AccessKey')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.SecretKey))
            {
                throw [ArgumentException]::new('AWS IAM user secret key cannot be blank.', 'Arguments.SecretKey')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.TerraformWorkingDirectory))
            {
                throw [ArgumentException]::new('Terraform working directory cannot be blank.', 'Arguments.TerraformWorkingDirectory')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.TerraformThreads))
            {
                throw [ArgumentException]::new('Terraform threads cannot be blank.', 'Arguments.TerraformThreads')
            }
            break
        }
        'Azure' 
        {  
            if ([string]::IsNullOrWhiteSpace($Arguments.ClientId))
            {
                throw [ArgumentException]::new('The ClientId cannot be blank.', 'Arguments.ClientId')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.ClientSecret))
            {
                throw [ArgumentException]::new('The Client Secret cannot be blank.', 'Arguments.ClientSecret')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.SubscriptionId))
            {
                throw [ArgumentException]::new('The SubscriptionId cannot be blank.', 'Arguments.SubscriptionId')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.TenantId))
            {
                throw [ArgumentException]::new('The TenantId cannot be blank.', 'Arguments.TenantId')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.ResourceGroup))
            {
                throw [ArgumentException]::new('The ResourceGroup cannot be blank.', 'Arguments.ResourceGroup')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.StorageAccountName))
            {
                throw [ArgumentException]::new('The StorageAccountName cannot be blank.', 'Arguments.StorageAccountName')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.ContainerName))
            {
                throw [ArgumentException]::new('The ContainerName cannot be blank.', 'Arguments.ContainerName')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.StandardBlobTier))
            {
                throw [ArgumentException]::new('The StandardBlobTier cannot be blank.', 'Arguments.StandardBlobTier')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.TerraformWorkingDirectory))
            {
                throw [ArgumentException]::new('Terraform working directory cannot be blank.', 'Arguments.TerraformWorkingDirectory')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.TerraformThreads))
            {
                throw [ArgumentException]::new('Terraform threads cannot be blank.', 'Arguments.TerraformThreads')
            }
        }
        'Local' 
        {
            if ([string]::IsNullOrWhiteSpace($Arguments.VMPoolBaseUrl))
            {
                throw [ArgumentException]::new('The base URL of VMPool cannot be blank.', 'Arguments.VMPoolBaseUrl')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.VMPoolAuthToken))
            {
                throw [ArgumentException]::new('The auth token to be used for VMPool cannot be blank.', 'Arguments.VMPoolAuthToken')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.LocalStackCreationTimeout))
            {
                throw [ArgumentException]::new('Local stack execution timeout, in minutes, cannot be blank.', 'Arguments.LocalStackCreationTimeout')
            }
            break
        }
        default
        {
            throw [ArgumentException]::new("Unexpected infrastructure type ""$($Arguments.InfrastructureType)"".", 'Arguments.InfrastructureType')
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($Arguments.ConfigurationFilePath))
    {
        throw [ArgumentException]::new('The path of the configuration file cannot be blank.', 'Arguments.ConfigurationFilePath')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.InstallerUrl))
    {
        throw [ArgumentException]::new('The installer URL cannot be blank.', 'Arguments.InstallerUrl')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.McConsoleUser))
    {
        throw [ArgumentException]::new('The McConsole UserName cannot be blank.', 'Arguments.McConsoleUser')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.McDbUser))
    {
        throw [ArgumentException]::new('The McDbUserName cannot be blank.', 'Arguments.McDbUser')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.McServerUsername))
    {
        throw [ArgumentException]::new('The McServer Username cannot be blank.', 'Arguments.McServerUsername')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.DeviceFamilies))
    {
        throw [ArgumentException]::new('The comma-separated device families cannot be blank.', 'Arguments.DeviceFamilies')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.OutType))
    {
        throw [ArgumentException]::new('The name of output type cannot be blank.', 'Arguments.OutType')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.OutFile))
    {
        throw [ArgumentException]::new('The path to templated output filepath cannot be blank.', 'Arguments.OutFile')
    }
    if ([Object]::ReferenceEquals($Arguments.StackCreationParameters, $null))
    {
        throw [ArgumentNullException]::new('Arguments.StackCreationParameters', 'Stack creation parameters are required.')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.Pipeline))
    {
        throw [ArgumentException]::new('The Pipeline cannot be blank.', 'Arguments.Pipeline')
    }

    function Update-StackParameters
    {
        [CmdletBinding(PositionalBinding = $false)]
        param
        (
            [Parameter(ValueFromPipeline = $true)]
            [psobject] $InputObject,

            [Parameter()]
            [string] $PropertyName
        )
        process
        {
            if ([object]::ReferenceEquals($InputObject, $null))
            {
                throw [ArgumentNullException]::new('InputObject')
            }
            if ([string]::IsNullOrWhiteSpace($PropertyName))
            {
                throw [ArgumentException]::new('The name of the property cannot be blank.', 'PropertyName')
            }

            [bool] $propertyExists = ($InputObject.PSObject.Properties | ? { $_.Name -clike "$PropertyName" }).Count -ne 0

            if (!$propertyExists)
            {
                throw [ArgumentException]::new(
                    "The specified input object does not have a property with the name ""$PropertyName"".",
                    'InputObject')
            }
                
            $InputObject.PSObject.Properties | ? { $_.Name -ilike $PropertyName } | Sort-Object -Property Name `
                | % `
                    {
                        [string] $value = $_.Value
                        [string] $name = $_.name -split ('-') | Select-Object -First 1
                        [string] $type = $_.name -split ('-') | Select-Object -Last 1
                        [string] $index = $_.name -split ('-') | Select-Object -First 1 -Skip 1
                        [string] $finalName = $name + $type + $index

                        if ($index -ceq $type)
                        {
                            [string] $finalName = $name + $type
                        }
                        else
                        {
                            [string] $finalName = $name + $type + $index
                        }
                
                        $InputObject.PSObject.Properties.Remove($_.Name) | Out-Null
                        $InputObject | Add-Member -MemberType NoteProperty -Name $finalName -Value $value | Out-Null
                    }
            return $InputObject
        }
    }

    function Set-StackOuput
    {
        [CmdletBinding(PositionalBinding = $false)]
        param
        (
            [Parameter()]
            [string] $OutFile,

            [Parameter()]
            [string] $TerraformWorkingDirectory
        )

        process
        {
            if (!(Test-Path -LiteralPath $OutFile -PathType Leaf))
            {
                throw [FileNotFoundException]::new("The file ""$OutFile"" is not found.", $OutFile)
            }

            [psobject] $rawStackOutput = Get-Content -Path $OutFile | ConvertFrom-Json
            [hashtable] $flatcontent = @{}
        
            [string[]] $rawStackOutputKeys = $rawStackOutput.PSObject.Properties | % {$_.Name}
        
            foreach($rawStackOutputKey in $rawStackOutputKeys)
            {
                [psobject] $indKeys = $rawStackOutput.$rawStackOutputKey.value.PSObject.Properties | % {$_.Name}
                foreach($key in $indKeys)
                {
                    $finalValue = $rawStackOutput.$rawStackOutputKey.value.$key
                    if($finalValue -is [System.Array])
                    {
                        $finalValue = $finalValue[0]
                    }
                    $flatcontent.Add($key, $finalValue)
                }
            }
                    
            [string] $interimOutputFilePath = "$TerraformWorkingDirectory/interimStackOutput.json"

            $flatcontent | ConvertTo-Json | Out-File -FilePath $interimOutputFilePath -Force -Encoding utf8

            [psobject] $cloudStackInfo = Get-Content -Raw -LiteralPath $interimOutputFilePath | ConvertFrom-Json

            $cloudStackInfo = Update-StackParameters -InputObject $cloudStackInfo -PropertyName '*InstanceId*'
            $cloudStackInfo = Update-StackParameters -InputObject $cloudStackInfo -PropertyName '*PublicIp*'
            $cloudStackInfo = Update-StackParameters -InputObject $cloudStackInfo -PropertyName '*PublicDnsName*'
            $cloudStackInfo = Update-StackParameters -InputObject $cloudStackInfo -PropertyName '*PrivateIp*'
                    
            [string] $mobiControlUrlDns = $cloudStackInfo.MsPublicDnsName
            [string] $mobiControlUrl = "https://$mobiControlUrlDns/MobiControl"
            $cloudStackInfo | Add-Member -MemberType NoteProperty -Name 'MobiControlUrl' -Value $mobiControlUrl

            return $cloudStackInfo
        }
    }

    [string] $generatePasswordProperty = '#GeneratePassword'
    [string] $passwordCharacterSetsProperty = '#CharacterSets'
}
process
{
    [string] $resolvedConfigurationFilePath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.ConfigurationFilePath,
        [RelativePathRequirements]::MustBelong -bor [RelativePathRequirements]::MustExist)

    [psobject] $configurationData = $resolvedConfigurationFilePath | Get-ConfigurationData

    [string] $outFile = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.OutFile,
        [RelativePathRequirements]::MustBelong)

    [ValidateNotNullOrEmpty()] [string] $stackName = $configurationData.StackName
    [ValidateNotNullOrEmpty()] [string] $infrastructureType = $configurationData.InfrastructureType

    [hashtable] $cfStackParameters = @{}

    $Arguments.StackCreationParameters.PSObject.Properties `
        | % `
        {
            [string] $name = $_.Name
            [object] $value = $_.Value
            if ($value -is [psobject] -and $value.$generatePasswordProperty -is [int])
            {
                [object] $characterSetsValue = $value.$passwordCharacterSetsProperty

                [RandomPasswordCharacterSets] $characterSets = [RandomPasswordCharacterSets]::All
                if (![object]::ReferenceEquals($characterSetsValue, $null))
                {
                    if ($characterSetsValue -isnot [string] -or ![enum]::TryParse([string]$characterSetsValue, $true, [ref] $characterSets))
                    {
                        throw "Invalid value of the property ""$passwordCharacterSetsProperty"" for the stack creation parameter ""$name"": $($characterSetsValue | ConvertTo-Json -Compress)."
                    }
                }

                [int] $passwordLength = $value.$generatePasswordProperty
                $value = New-RandomPassword -Length $passwordLength -CharacterSets $characterSets
                Write-Verbose -Verbose "[CF Parameters] Generated password: $name = ""$value"""
            }

            $cfStackParameters.Add($name, $value) | Out-Null
        }

    $cfStackParameters.Add('StackName', $stackName) | Out-Null

    [psobject] $stackInfo = `
        switch ($InfrastructureType)
        {
            'AWS' 
            {
                [string] $AwsS3BucketName = 'terraform-soti-devops'

                Invoke-TerraformStack `
                    -CloudPlatformName $InfrastructureType `
                    -StackName $stackName `
                    -StackCreationParameters $cfStackParameters `
                    -TerraformCliMinimumVersion $Arguments.TerraformMinimumVersion `
                    -TerraformWorkingDirectory $Arguments.TerraformWorkingDirectory `
                    -TerraformThreads $Arguments.TerraformThreads `
                    -OutType $Arguments.OutType `
                    -AwsAccessKey $Arguments.AccessKey `
                    -AwsSecretKey $Arguments.SecretKey `
                    -AwsRegion $Arguments.Region `
                    -AwsCliMinimumVersion $Arguments.AwsMinimumVersion `
                    -AwsS3BucketName $AwsS3BucketName `
                    -OutFile $outFile `
                    -verbose `
                    | Out-Null
                
                [psobject] $awsStackInfo = Set-StackOuput `
                    -OutFile $outFile `
                    -TerraformWorkingDirectory $Arguments.TerraformWorkingDirectory

                $awsStackInfo

                break
            }
            'Azure' 
            {
                [string] $pipeline = $Arguments.Pipeline
                Invoke-TerraformStack `
                    -CloudPlatformName $InfrastructureType `
                    -StackName "$pipeline/$stackName" `
                    -StackCreationParameters $cfStackParameters `
                    -TerraformCliMinimumVersion $Arguments.TerraformMinimumVersion `
                    -TerraformWorkingDirectory $Arguments.TerraformWorkingDirectory `
                    -TerraformThreads $Arguments.TerraformThreads `
                    -OutType $Arguments.OutType `
                    -ClientId $Arguments.ClientId `
                    -ClientSecret $Arguments.ClientSecret `
                    -SubscriptionId $Arguments.SubscriptionId `
                    -TenantId $Arguments.TenantId `
                    -ResourceGroup $Arguments.ResourceGroup `
                    -StorageAccountName $Arguments.StorageAccountName `
                    -ContainerName $Arguments.ContainerName `
                    -StandardBlobTier $Arguments.StandardBlobTier `
                    -OutFile $outFile `
                    -verbose `
                    | Out-Null
                
                [psobject] $azureStackInfo = Set-StackOuput `
                    -OutFile $outFile `
                    -TerraformWorkingDirectory $Arguments.TerraformWorkingDirectory

                $azureStackInfo

                break
            }
            'Local' 
            {
                [string] $resolvedInstanceDefinitionFilePath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
                    $Arguments.InstanceDefinitionFilePath,
                    [RelativePathRequirements]::MustBelong -bor [RelativePathRequirements]::MustExist)

                New-LocalStack `
                    -InfrastructureType $infrastructureType `
                    -VmPoolBaseUrl $Arguments.VMPoolBaseUrl `
                    -VmPoolAuthToken $Arguments.VMPoolAuthToken `
                    -StackName $stackName `
                    -InstanceDefinitionDataFilePath $resolvedInstanceDefinitionFilePath `
                    -LocalStackCreationTimeout $Arguments.LocalStackCreationTimeout `
                    -CfStackParameters $cfStackParameters `
                    -OutFile $outFile `
                    -StackCreationParameters $Arguments.StackCreationParameters `
                    | Out-Null
                
                [psobject] $localStackInfo = Get-Content -Raw -LiteralPath $outFile | ConvertFrom-Json

                $localStackInfo
                break
            }
            default
            {
                throw [ArgumentException]::new("Unexpected infrastructure type ""$InfrastructureType"".", 'InfrastructureType')
            }
        }
    
    $stackInfo | Add-Member -MemberType NoteProperty -Name 'MobiControlInstallerUrl' -Value $Arguments.InstallerUrl
    $stackInfo | Add-Member -MemberType NoteProperty -Name 'MobiControlDeviceFamilies' -Value $Arguments.DeviceFamilies
    $stackInfo | Add-Member -MemberType NoteProperty -Name 'WindowsUserName' -Value $Arguments.McConsoleUser
    $stackInfo | Add-Member -MemberType NoteProperty -Name 'MobiControlUserName' -Value $Arguments.McServerUsername
    $stackInfo | Add-Member -MemberType NoteProperty -Name 'SqlServerUserName' -Value $Arguments.McDbUser
    $stackInfo | Add-Member -MemberType NoteProperty -Name 'MobiControlDatabaseName' -Value $Arguments.MobiControlDatabaseName -Force

    $stackInfo | Set-StackInfoFileContent -LiteralPath $outFile
    Write-MinorLogSeparator
    $outFile | Get-StackInfo -Print | Out-Null
}

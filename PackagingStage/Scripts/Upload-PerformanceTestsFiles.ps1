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
.REQUIREDSCRIPTS Soti.Utilities:[1.0.0,1.9999.9999], Soti.Utilities.IO:[1.0.0,1.9999.9999], Soti.Utilities.Aws:[1.1.0,1.9999.9999], Soti.Utilities.Cloud:[1.0.0,1.9999.9999]
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.DESCRIPTION N/A

#>

#Requires -Version 5

using namespace System
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace System.IO
using namespace System.Security.Cryptography

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
    . 'Soti.Utilities.Aws.ps1'
    . 'Soti.Utilities.Cloud.ps1'
    . "$PSScriptRoot\..\..\.CloudFiles\Publish-ToArtifactoryUsingCli.ps1"

    if ([string]::IsNullOrWhiteSpace($Arguments.InfrastructureType))
    {
        throw [ArgumentException]::new("The type of the infrastructure used cannot be blank.", 'Arguments.InfrastructureType')
    }

    switch ($Arguments.InfrastructureType)
    {
        'AWS' 
        {  
            if ([string]::IsNullOrWhiteSpace($Arguments.Bucket))
            {
                throw [ArgumentException]::new("The name of the S3 bucket to upload files cannot be blank.", 'Arguments.Bucket')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.Region))
            {
                throw [ArgumentException]::new("The name of the AWS region cannot be blank.", 'Arguments.Region')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.AccessKey))
            {
                throw [ArgumentException]::new("The AWS access key cannot be blank.", 'Arguments.AccessKey')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.SecretKey))
            {
                throw [ArgumentException]::new("The AWS secret key cannot be blank.", 'Arguments.SecretKey')
            }
            break
        }
        'Azure' 
        {  
            if ([string]::IsNullOrWhiteSpace($Arguments.ClientId))
            {
                throw [ArgumentException]::new("The ClientId cannot be blank.", 'Arguments.ClientId')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.ClientSecret))
            {
                throw [ArgumentException]::new("The Client Secret cannot be blank.", 'Arguments.ClientSecret')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.SubscriptionId))
            {
                throw [ArgumentException]::new("The SubscriptionId cannot be blank.", 'Arguments.SubscriptionId')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.TenantId))
            {
                throw [ArgumentException]::new("The TenantId cannot be blank.", 'Arguments.TenantId')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.ResourceGroup))
            {
                throw [ArgumentException]::new("The ResourceGroup cannot be blank.", 'Arguments.ResourceGroup')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.StorageAccountName))
            {
                throw [ArgumentException]::new("The StorageAccountName cannot be blank.", 'Arguments.StorageAccountName')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.ContainerName))
            {
                throw [ArgumentException]::new("The ContainerName cannot be blank.", 'Arguments.ContainerName')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.StandardBlobTier))
            {
                throw [ArgumentException]::new("The StandardBlobTier cannot be blank.", 'Arguments.StandardBlobTier')
            }
            break
        }
        'Local' 
        {
            if ([string]::IsNullOrWhiteSpace($Arguments.ArtifactoryUrl))
            {
                throw [ArgumentException]::new("The Artifactory server URL cannot be blank.", 'Arguments.ArtifactoryUrl')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.ArtifactoryRepository))
            {
                throw [ArgumentException]::new("The Artifactory repository cannot be blank.", 'Arguments.ArtifactoryRepository')
            }
            if ([string]::IsNullOrWhiteSpace($Arguments.ArtifactoryAccessToken))
            {
                throw [ArgumentException]::new("The Artifactory access token cannot be blank.", 'Arguments.ArtifactoryAccessToken')
            }
            break
        }
        default
        {
            throw [ArgumentException]::new("Unexpected infrastructure type ""$($Arguments.InfrastructureType)"".", 'Arguments.InfrastructureType')
        }
    }

    if ([string]::IsNullOrWhiteSpace($Arguments.Pipeline))
    {
        throw [ArgumentException]::new("The name of the current pipeline cannot be blank.", 'Arguments.Pipeline')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.PackageFileName))
    {
        throw [ArgumentException]::new("The package file name cannot be blank.", 'Arguments.PackageFileName')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.OutputConfigurationFilePath))
    {
        throw [ArgumentException]::new("The path of the output configuration file cannot be blank.", 'Arguments.OutputConfigurationFilePath')
    }
    if (Test-NullOrEmptyArray $Arguments.SourceItems)
    {
        throw [ArgumentException]::new("A non-empty array of the templated source items is required.", 'Arguments.SourceItems')
    }
}
process
{
    try
    {
        [string] $resolvedOutputConfigurationFilePath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.OutputConfigurationFilePath,
        [RelativePathRequirements]::MustBelong)

        [string] $intermediateDirectory = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
            "`$Root:package_contents_$([guid]::NewGuid().ToString('N'))",
            [RelativePathRequirements]::MustBelong)

        Ensure-DirectoryExists -LiteralPath $intermediateDirectory -Clean

        foreach ($sourceItem in $Arguments.SourceItems)
        {
            [string] $sourceItemPath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
                $sourceItem,
                [RelativePathRequirements]::MustBelong -bor [RelativePathRequirements]::MustExist)

            [string] $sourceItemName = [Path]::GetFileName($sourceItemPath)
            [string] $itemDestinationPath = [Path]::Combine($intermediateDirectory, $sourceItemName)

            Move-Item -LiteralPath $sourceItemPath -Destination $itemDestinationPath -Force -Verbose
        }

        [string] $packageDirectory = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
            "`$Root:package_$([guid]::NewGuid().ToString('N'))",
            [RelativePathRequirements]::MustBelong)

        Ensure-DirectoryExists -LiteralPath $packageDirectory -Clean

        [string] $zipArchivePath = Expand-RelativePath -BaseDir $packageDirectory -RelativePath $Arguments.PackageFileName -MustBelong

        [string] $itemWildcard = [Path]::Combine($intermediateDirectory, '*')
        Compress-Archive -Path $itemWildcard -DestinationPath $zipArchivePath

        [RandomNumberGenerator] $rng = [RNGCryptoServiceProvider]::Create()
        [byte[]] $randomIdBytes = [byte[]]::new(4)
        $rng.GetBytes($randomIdBytes) | Out-Null
        [string] $randomId = ($randomIdBytes | % { $_.ToString('x2') }) -join ''

        [string] $sanitizedBranchName = $CommonArguments.BranchName -replace '[^a-zA-Z0-9-]', '-'
        [string] $environmentId = "$sanitizedBranchName-$($CommonArguments.VersionBuildNumber)-$randomId"
        [string] $fileName = [Path]::GetFileName($zipArchivePath)
        [string] $sanitizedPipeline = $Arguments.Pipeline -replace '[^a-zA-Z0-9-]', '-'
        [string] $fileKey = "$sanitizedPipeline/$environmentId/$fileName"


        [string] $packageFileUrl = `
            switch ($Arguments.InfrastructureType)
            {
                'AWS' 
                {  
                    Copy-FileToS3 `
                        -FilePath $zipArchivePath `
                        -FileKey $fileKey `
                        -BucketName $Arguments.Bucket `
                        -AccessKey $Arguments.AccessKey `
                        -SecretKey $Arguments.SecretKey `
                        -Region $Arguments.Region | Out-Null

                    "https://s3.amazonaws.com/$($Arguments.Bucket)/$fileKey"
                    break
                }
                'Azure' 
                {  
                    $fileKey = "$sanitizedPipeline/$environmentId"

                    Copy-FilesToCloudStorage `
                        -CloudPlatform $Arguments.InfrastructureType `
                        -Files $zipArchivePath `
                        -ClientId $Arguments.ClientId `
                        -ClientSecret $Arguments.ClientSecret `
                        -TenantId $Arguments.TenantId `
                        -SubscriptionId $Arguments.SubscriptionId `
                        -ResourceGroup $Arguments.ResourceGroup `
                        -StorageAccountName $Arguments.StorageAccountName `
                        -ContainerName $Arguments.ContainerName `
                        -StandardBlobTier $Arguments.StandardBlobTier `
                        -BlobFolder $fileKey `
                        -LocalBaseDirectory $(Split-Path -Path $zipArchivePath) `
                        -Force | Out-Null

                    "https://$($Arguments.StorageAccountName).blob.core.windows.net/$($Arguments.ContainerName)/$fileKey/$fileName"
                    break
                }
                'Local' 
                {
                    [string[]] $uploadFileList = @("$zipArchivePath")
                    [string] $artifactorySubPath = "$sanitizedPipeline/$environmentId"

                    Publish-ToArtifactory `
                        -ArtifactoryUrl $Arguments.ArtifactoryUrl `
                        -ArtifactoryRepository $Arguments.ArtifactoryRepository `
                        -ArtifactoryAccessToken $Arguments.ArtifactoryAccessToken `
                        -ArtifactorySubPath $artifactorySubPath `
                        -FileListLiteralPath $uploadFileList | Out-Null

                    "$($Arguments.ArtifactoryUrl)/$($Arguments.ArtifactoryRepository)/$fileKey"
                    break
                }
                default
                {
                    throw [ArgumentException]::new("Unexpected infrastructure type ""$($Arguments.InfrastructureType)"".", 'Arguments.InfrastructureType')
                }
            }

        [string] $stackName = "$sanitizedPipeline-$environmentId"
        [psobject] $outputConfigurationData = [psobject]::new() `
            | Add-Member -PassThru -MemberType NoteProperty -Name PackageFileUrl -Value $packageFileUrl `
            | Add-Member -PassThru -MemberType NoteProperty -Name StackName -Value $stackName `
            | Add-Member -PassThru -MemberType NoteProperty -Name InfrastructureType -Value $Arguments.InfrastructureType

        if ($Arguments.InfrastructureType -ieq 'Azure')
        {
            $outputConfigurationData `
                | Add-Member -PassThru -MemberType NoteProperty -Name StorageContainerName -Value $Arguments.ContainerName `
                | Add-Member -PassThru -MemberType NoteProperty -Name StorageBlob -Value "$fileKey" `
                | Add-Member -PassThru -MemberType NoteProperty -Name PackageFilePath -Value "$fileKey/$fileName"
        }

        Remove-Item -Recurse -Force -LiteralPath $intermediateDirectory
        Remove-Item -Recurse -Force -LiteralPath $packageDirectory

        Write-Host ''
        Write-Host 'Output configuration:'
        $outputConfigurationData | Format-List -Property * | Out-Host
        Write-Host ''

        $outputConfigurationData `
            | ConvertTo-Json `
            | Set-Content -LiteralPath $resolvedOutputConfigurationFilePath -Encoding UTF8 -Force
    }
    catch
    {
        [string] $errorDetails = Get-ErrorDetails
        Write-Host -ForegroundColor Red $errorDetails

        throw
    }
}

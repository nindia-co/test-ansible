<#PSScriptInfo

.VERSION 0.0.0
.GUID ef645c44-7795-41a8-8ef5-7a846eed6690
.AUTHOR DevOps Team
.COMPANYNAME SOTI Inc.
.COPYRIGHT Copyright (C) SOTI Inc.
.TAGS
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS Soti.Utilities:[1.0.0,1.9999.9999], Soti.Utilities.IO:[1.0.0,1.9999.9999], Soti.Diagnostics.Logging:[1.0.0,1.9999.9999], Soti.Utilities.Cloud:[1.0.0,1.9999.9999]
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.DESCRIPTION N/A

#>

#Requires -Version 5

using namespace System
using namespace System.Collections.Generic
using namespace System.Data
using namespace System.Diagnostics
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Threading

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
    . 'Soti.Utilities.Cloud.ps1'
    . 'Soti.Diagnostics.Logging.ps1'

    [string] $commonScriptPath = "$PSScriptRoot\..\..\.Common\Scripts\Common.ps1"
    . $commonScriptPath

    if ([string]::IsNullOrWhiteSpace($Arguments.InfrastructureType))
    {
        throw [ArgumentException]::new('The infrastructure type cannot be blank.', 'Arguments.InfrastructureType')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.VMPoolBaseUrl))
    {
        throw [ArgumentException]::new('The base URL of VMPool cannot be blank.', 'Arguments.VMPoolBaseUrl')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.VMPoolAuthToken))
    {
        throw [ArgumentException]::new('The auth token to be used for VMPool cannot be blank.', 'Arguments.VMPoolAuthToken')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.MobiControlFunctionalityType))
    {
        throw [ArgumentException]::new('The Scenario needs to be selected.', 'Arguments.MobiControlFunctionalityType')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.DeviceFamilies))
    {
        throw [ArgumentException]::new('The comma-separated device families cannot be blank.', 'Arguments.DeviceFamilies')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.VmHostServiceUserName))
    {
        throw [ArgumentException]::new('The Service account username must be specified.', 'Arguments.VmHostServiceUserName')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.VmHostServiceUserPassword))
    {
        throw [ArgumentException]::new('The Service account password must be specified.', 'Arguments.VmHostServiceUserPassword')
    }

    if ($Arguments.InfrastructureType -ieq 'Azure')
    {
        if ([string]::IsNullOrWhiteSpace($Arguments.ClientId))
        {
            throw [ArgumentException]::new("The Client Id cannot be blank.", 'Arguments.ClientId')
        }
        if ([string]::IsNullOrWhiteSpace($Arguments.ClientSecret))
        {
            throw [ArgumentException]::new("The Client Secret cannot be blank.", 'Arguments.ClientSecret')
        }
        if ([string]::IsNullOrWhiteSpace($Arguments.SubscriptionId))
        {
            throw [ArgumentException]::new("The Subscription Id cannot be blank.", 'Arguments.SubscriptionId')
        }
        if ([string]::IsNullOrWhiteSpace($Arguments.TenantId))
        {
            throw [ArgumentException]::new("The Tenant Id cannot be blank.", 'Arguments.TenantId')
        }
        if ([string]::IsNullOrWhiteSpace($Arguments.ResourceGroup))
        {
            throw [ArgumentException]::new("The Resource Group cannot be blank.", 'Arguments.ResourceGroup')
        }
        if ([string]::IsNullOrWhiteSpace($Arguments.StorageAccountName))
        {
            throw [ArgumentException]::new("The Storage Account Name cannot be blank.", 'Arguments.StorageAccountName')
        }
    }

    if ([string]::IsNullOrWhiteSpace($Arguments.DevOpsDataRootDir))
    {
        throw [ArgumentException]::new(
            'The path of the DevOps data root directory cannot be blank.',
            'Arguments.DevOpsDataRootDir')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.ConfigurationFilePath))
    {
        throw [ArgumentException]::new('The path of the configuration file cannot be blank.', 'Arguments.ConfigurationFilePath')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.StackInfoFilePath))
    {
        throw [ArgumentException]::new(
            'The path of the stack information file cannot be blank.',
            'Arguments.StackInfoFilePath')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.Pipeline))
    {
        throw [ArgumentException]::new("The name of current pipeline cannot be blank.", 'Arguments.Pipeline')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.Bucket))
    {
        throw [ArgumentException]::new("The name of the dynamic data S3 bucket cannot be blank.", 'Arguments.Bucket')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.TimeZone))
    {
        throw [ArgumentException]::new("The time zone cannot be blank.", 'Arguments.TimeZone')
    }
    if (!(Test-Null $Arguments.OpenFirewallPorts.Inbound) -and [object]::ReferenceEquals($Arguments.OpenFirewallPorts.Inbound -as [int[]], $null))
    {
        throw [ArgumentException]::new("The firewall ports must an array of integers, if specified.", 'Arguments.OpenFirewallPorts.Inbound')
    }
    if (Test-NullOrEmptyArray $Arguments.Instances)
    {
        throw [ArgumentException]::new("An array of instances to process must be specified.", 'Arguments.Instances')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.CommonStepsTimeout))
    {
        throw [ArgumentException]::new("The timeout of the common steps cannot be blank.", 'Arguments.CommonStepsTimeout')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.SearchServiceName))
    {
        throw [ArgumentException]::new("The SearchServiceName cannot be blank.", 'Arguments.SearchServiceName')
    }
    if ([string]::IsNullOrWhiteSpace($Arguments.SearchServiceDeploymentType))
    {
        throw [ArgumentException]::new("The SearchServiceDeploymentType cannot be blank.", 'Arguments.SearchServiceDeploymentType')
    }

    [timespan] $commonStepsTimeout = [timespan]::Zero
    if (![timespan]::TryParse($Arguments.CommonStepsTimeout, [ref] $commonStepsTimeout) -or $commonStepsTimeout -le [timespan]::Zero)
    {
        throw [ArgumentException]::new("The timeout of the common steps must be a positive time span value.", 'Arguments.CommonStepsTimeout')
    }

    [int] $commonStepsTimeoutInSeconds = [Convert]::ToInt32($commonStepsTimeout.TotalSeconds)
    [int] $waitJobTimeoutInSeconds = [Math]::Min(15, $commonStepsTimeoutInSeconds)

    [string] $cfOutputProperty = '#CFOutput'
}
process
{
    function Restart-RemoteMachines
    {
        [string[]] $flattenedInstanceAddresses = @($flattenedInstances | % { $_.Address })
        [string] $flattenedInstanceAddressesString = ($flattenedInstanceAddresses | % { """$_""" }) -join ', '

        Write-Host "Restarting the remote machines $flattenedInstanceAddressesString..."

        if ($Arguments.InfrastructureType -ieq 'Azure')
        {
            Restart-AzureVMs `
                -ClientId $Arguments.ClientId `
                -ClientSecret $Arguments.ClientSecret `
                -SubscriptionId  $Arguments.SubscriptionId `
                -TenantId $Arguments.TenantId `
                -ResourceGroup $azureVmResourceGroup
        }
        else
        {
            Restart-Computer `
                -Credential $remoteControlCredential `
                -ComputerName $flattenedInstanceAddresses `
                -Wait `
                -For PowerShell `
                -Protocol WSMan `
                -WsmanAuthentication Negotiate `
                -Force
        }

        Write-Host "Restarting the remote machines $flattenedInstanceAddressesString - DONE."

        Write-MinorLogSeparator
        [timespan] $restartCoolOffInterval = [timespan]::FromMinutes(2)
        Write-Host "Sleeping for $restartCoolOffInterval to allow the machines to cool off after the restart."
        [Thread]::Sleep($restartCoolOffInterval) | Out-Null

        Write-MinorLogSeparator
        Write-Host "Checking the state of the remote machines after the restart."

        foreach ($instance in $flattenedInstances)
        {
            Write-MinorLogSeparator

            Execute-RemoteScript `
                -Credential $remoteControlCredential `
                -ComputerName $instance.Address `
                -ComputerTitle $instance.Title `
                -ArgumentList @($Arguments.InfrastructureType) `
                -ScriptBlock `
                    {
                        param ([string] $InfrastructureType)
                        Get-Process -ErrorAction SilentlyContinue `
                            | Sort-Object -Property ProcessName, Id -ErrorAction SilentlyContinue `
                            | Format-Table `
                                -AutoSize `
                                -Property ProcessName, Id, StartTime, PriorityClass, SessionId, Path `
                                -ErrorAction SilentlyContinue `
                            | Out-Host
                    }
        }

    }
    try
    {
        [string] $resolvedConfigurationFilePath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
        $Arguments.ConfigurationFilePath,
        [RelativePathRequirements]::MustBelong -bor [RelativePathRequirements]::MustExist)

        [bool] $comPlusVariableForDS = $Arguments.MobiControlFunctionalityType -eq 'FileTransfer'

        [psobject] $configurationData = $resolvedConfigurationFilePath | Get-ConfigurationData

        [string] $resolvedStackInfoFilePath = $CommonArguments.Utilities.TemplatedRelativePathResolver.Resolve(
            $Arguments.StackInfoFilePath,
            [RelativePathRequirements]::MustBelong -bor [RelativePathRequirements]::MustExist)

        [psobject] $stackInfo = $resolvedStackInfoFilePath | Get-StackInfo
        [pscredential] $remoteControlCredential = $stackInfo | New-WindowsAdministratorCredential

        [ValidateNotNullOrEmpty()] [string] $artifactsFileUrl = $configurationData.PackageFileUrl

        [string] $storageContainerName = $null
        [string] $packageFilePath = $null
        [string] $azureVmResourceGroup = $null

        if ($Arguments.InfrastructureType -ieq 'Azure')
        {
            [ValidateNotNullOrEmpty()] $storageContainerName = $configurationData.StorageContainerName
            [ValidateNotNullOrEmpty()] $packageFilePath = $configurationData.PackageFilePath
            [ValidateNotNullOrEmpty()] $azureVmResourceGroup = $configurationData.StackName
        }

        [object[]] $commonPostInitializationScripts = $Arguments.CommonPostInitializationScripts -as [object[]]

        [psobject[]] $flattenedInstances = @()
        [string[]] $allPublicFqdns = @()
        [string[]] $allPublicIps = @()
        [string[]] $allPrivateIps = @()
        [string[]] $parsedDeviceFamilies = ($Arguments.DeviceFamilies -split ',') | % { $_.Trim() }

        [psobject] $instance = $null
        foreach ($instance in $Arguments.Instances)
        {
            [string] $instanceName = $instance.Name
            if ([string]::IsNullOrWhiteSpace($instanceName))
            {
                throw [ArgumentException]::new('The name of the instance cannot be blank.', '$Arguments.Instances[].Name')
            }

            [string] $friendlyName = $instance.FriendlyName
            if ([string]::IsNullOrWhiteSpace($friendlyName))
            {
                $friendlyName = $instanceName
            }

            if($Arguments.SearchServiceDeploymentType -ieq 'ms_vm' -and $friendlyName -ieq 'Soti Search')
            {
                Write-Host 'Skipping installation of "SOTI search on separate box", as its already installed along with MobiControl Management Service.'
                continue
            }

            [string] $stackCreationPropertyPrefix = $instance.StackCreationPropertyPrefix
            if ([string]::IsNullOrWhiteSpace($stackCreationPropertyPrefix))
            {
                $stackCreationPropertyPrefix = $instanceName
            }

            [bool] $multiInstance = $instance.MultiInstance | As-Boolean

            [object[]] $initializationScripts = @()
            if ($instance.InitializationScripts -is [object[]])
            {
                $initializationScripts += $instance.InitializationScripts
            }
            if ($commonPostInitializationScripts -is [object[]])
            {
                $initializationScripts += $commonPostInitializationScripts
            }

            [string] $methodArgumentName = if ($multiInstance) { 'PropertyPrefix' } else { 'Property' }

            [hashtable] $publicFqdnMethodArguments = @{ $methodArgumentName = "$($stackCreationPropertyPrefix)PublicDnsName" }
            [string[]] $publicFqdns = $stackInfo | Get-ItemsFromStackInfo -Verify @publicFqdnMethodArguments
            $allPublicFqdns += $publicFqdns

            [hashtable] $publicIpMethodArguments = @{ $methodArgumentName = "$($stackCreationPropertyPrefix)PublicIp" }
            [string[]] $publicIps = $stackInfo | Get-ItemsFromStackInfo -Verify @publicIpMethodArguments
            $allPublicIps += $publicIps

            [hashtable] $privateIpMethodArguments = @{ $methodArgumentName = "$($stackCreationPropertyPrefix)PrivateIp" }
            [string[]] $privateIps = $stackInfo | Get-ItemsFromStackInfo -Verify @privateIpMethodArguments
            $allPrivateIps += $privateIps

            [string[]] $instanceAddresses = $publicIps
            [int] $instanceCount = $instanceAddresses.Count

            [int] $instanceIndex = 0
            foreach ($instanceAddress in $instanceAddresses)
            {
                $instanceIndex++
                [string] $instanceIndexString = if ($multiInstance) { " ($instanceIndex of $instanceCount)" } else { [string]::Empty }
                [string] $title = "$friendlyName instance$($instanceIndexString)"

                [psobject] $flattenedInstance = [psobject]::new() `
                    | Add-Member -PassThru -MemberType NoteProperty -Name Name -Value $instanceName `
                    | Add-Member -PassThru -MemberType NoteProperty -Name Address -Value $instanceAddress `
                    | Add-Member -PassThru -MemberType NoteProperty -Name Title -Value $title `
                    | Add-Member -PassThru -MemberType NoteProperty -Name InitializationScripts -Value $initializationScripts `
                    | Add-Member -PassThru -MemberType NoteProperty -Name ScriptArguments -Value $instance.ScriptArguments

                $flattenedInstances += $flattenedInstance
            }
        }

        [string[]] $allTrustedAddresses = $allPublicFqdns + $allPublicIps + $allPrivateIps

        [string[]] $allInstanceAddresses = @($flattenedInstances | % { $_.Address })
        Add-PSRemotingTrustedHosts -Hosts $allInstanceAddresses

        [string] $instanceNounSuffix = if ($flattenedInstances.Count -eq 1) { [string]::Empty } else { 's' }
        #Hack to allow winRM to be ready
        Write-Host 'Sleeping for 2 mins to allow WSMan time for winrm connection'
        Start-Sleep -Seconds 120
        #Hack
        if ($Arguments.InfrastructureType -ieq 'Local')
        {
            [ValidateNotNullOrEmpty()] [string] $stackName = $configurationData.StackName
            [pscredential] $hostCredential = [pscredential]::new("soti\$($Arguments.VmHostServiceUserName)", ($Arguments.VmHostServiceUserPassword | ConvertTo-SecureString -AsPlainText -Force))

            $hostVmMap = Get-VMPoolVmsInfo `
                -VmPoolBaseUrl $Arguments.VmPoolBaseUrl `
                -VmPoolAuthToken $Arguments.VmPoolAuthToken `
                -StackName $stackName

            Manage-LocalStack `
                -VmPoolBaseUrl $Arguments.VmPoolBaseUrl `
                -VmPoolAuthToken $Arguments.VmPoolAuthToken `
                -StackName $stackName `
                -Action 'shutDown' `
                | Out-Null

            foreach ($entry in $hostVmMap.GetEnumerator())
            {
                [string] $hostName = $entry.Key
                [string[]] $vmNames = $entry.Value

                foreach ($vmName in $vmNames)
                {
                    [int] $retryCount = 0
                    while($retryCount -le 5)
                    {
                        try
                        {
                            Execute-RemoteScript `
                                -Credential $hostCredential `
                                -ComputerName  $hostName `
                                -ComputerTitle $hostName `
                                -ArgumentList @($vmName) `
                                -ScriptBlock `
                                    {
                                        param ([string] $vmName)
                                        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                                        Microsoft.PowerShell.Core\Set-StrictMode -Version 1

                                        "Applying recommended network settings on host:$hostName for vm:$vmName"
            
                                        $vmNetworkAdapter = Get-VM $vmName | Get-VMNetworkAdapter
                                        $vmNetworkAdapter | Set-VMNetworkAdapter -IovQueuePairsRequested 2 -IovWeight 100 -VmmqEnabled $true
                                        # $vmNetworkAdapter | Set-VMNetworkAdapterRdma -RdmaWeight 100
                                    }
                            break
                        }
                        catch
                        {
                            $retryCount += 1
                            Start-Sleep -Seconds 30
                            if ($retryCount -ge 5)
                            {
                                throw 
                            }
                        }
                    }
                }
            }

            Manage-LocalStack `
                -VmPoolBaseUrl $Arguments.VmPoolBaseUrl `
                -VmPoolAuthToken $Arguments.VmPoolAuthToken `
                -StackName $stackName `
                -Action 'start' `
                | Out-Null
        }
        #Hack to allow winRM to be ready
        Write-Host 'Sleeping for 4 mins to allow WSMan time for winrm connection'
        Start-Sleep -Seconds 240
        #Hack

        Write-MinorLogSeparator
        Write-Host "Executing common setup steps for $($flattenedInstances.Count) instance$instanceNounSuffix in parallel."
        Write-Host ''

        [Stopwatch] $commonStepsJobStopwatch = [Stopwatch]::StartNew()

        [Job[]] $jobs = $flattenedInstances `
            | % `
            {
                Start-Job `
                    -Name "Executing common setup steps for $($_.Title)." `
                    -ArgumentList `
                        @(
                            $commonScriptPath,
                            $remoteControlCredential,
                            $Arguments.DevOpsDataRootDir,
                            $Arguments.TimeZone,
                            $artifactsFileUrl,
                            $storageContainerName,
                            $packageFilePath,
                            $Arguments.ClientId,
                            $Arguments.ClientSecret,
                            $Arguments.SubscriptionId,
                            $Arguments.TenantId,
                            $Arguments.ResourceGroup,
                            $azureVmResourceGroup,
                            $Arguments.StorageAccountName
                            $Arguments.OpenFirewallPorts.Inbound,
                            $Arguments.OpenFirewallPorts.Outbound,
                            $allTrustedAddresses,
                            $Arguments.InfrastructureType,
                            $_,
                            $stackInfo
                        ) `
                    -ScriptBlock `
                        {
                            # IMPORTANT: Since this script block is executed in a job, the fully qualified type names must be used here

                            param
                            (
                                [string] $CommonScriptPath,
                                [pscredential] $RemoteControlCredential,
                                [string] $DevOpsDataRootDir,
                                [string] $TimeZone,
                                [string] $ArtifactsFileUrl,
                                [string] $StorageContainerName,
                                [string] $PackageFilePath,
                                [string] $ClientId,
                                [string] $ClientSecret,
                                [string] $SubscriptionId,
                                [string] $TenantId,
                                [string] $ResourceGroup,
                                [string] $AzureVmResourceGroup,
                                [string] $StorageAccountName,
                                [int[]] $OpenFirewallInboundPorts,
                                [int[]] $OpenFirewallOutboundPorts,
                                [string[]] $TrustedHosts,
                                [string] $InfrastructureType,
                                [psobject] $FlattenedInstance,
                                [psobject] $StackInfo
                            )

                            $Script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                            Microsoft.PowerShell.Core\Set-StrictMode -Version 1

                            [string] $taskTitle = "Executing common setup steps for $($FlattenedInstance.Title)"
                            Write-Host "$taskTitle..."
                            [string] $taskStatus = 'SUCCEEDED'
                            [System.Diagnostics.Stopwatch] $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                            try
                            {
                                . $CommonScriptPath

                                Execute-RemoteScript `
                                    -Credential $RemoteControlCredential `
                                    -ComputerName $FlattenedInstance.Address `
                                    -ComputerTitle $FlattenedInstance.Title `
                                    -ArgumentList `
                                        @(
                                            $DevOpsDataRootDir,
                                            $InfrastructureType,
                                            $TimeZone,
                                            $ArtifactsFileUrl,
                                            $StorageContainerName,
                                            $PackageFilePath,
                                            $ClientId,
                                            $ClientSecret,
                                            $SubscriptionId,
                                            $TenantId,
                                            $ResourceGroup,
                                            $AzureVmResourceGroup,
                                            $StorageAccountName,
                                            $OpenFirewallInboundPorts,
                                            $OpenFirewallOutboundPorts,
                                            $TrustedHosts,
                                            $FlattenedInstance.InitializationScripts,
                                            $FlattenedInstance.Name,
                                            $FlattenedInstance.Address,
                                            $FlattenedInstance.Title,
                                            $StackInfo
                                        ) `
                                    -ScriptBlock `
                                        {
                                            # IMPORTANT: Since this script block is executed remotely, the fully qualified type names must be used here

                                            param
                                            (
                                                [string] $DevOpsDataRootDir,
                                                [string] $InfrastructureType,
                                                [string] $TimeZone,
                                                [string] $ArtifactsFileUrl,
                                                [string] $StorageContainerName,
                                                [string] $PackageFilePath,
                                                [string] $ClientId,
                                                [string] $ClientSecret,
                                                [string] $SubscriptionId,
                                                [string] $TenantId,
                                                [string] $ResourceGroup,
                                                [string] $AzureVmResourceGroup,
                                                [string] $StorageAccountName,
                                                [int[]] $OpenFirewallInboundPorts,
                                                [int[]] $OpenFirewallOutboundPorts,
                                                [string[]] $TrustedHosts,
                                                [object[]] $InitializationScripts,
                                                [string] $InstanceName,
                                                [string] $InstanceAddress,
                                                [string] $InstanceTitle,
                                                [psobject] $StackInfo
                                            )


                                            $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                                            Microsoft.PowerShell.Core\Set-StrictMode -Version 1
                                            $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

                                            Write-Host "Setting time zone ""$TimeZone""."
                                            Set-TimeZone -Id $TimeZone

                                            Write-Host "Disabling TLS 1.3."
                                            New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Server' -Force | Out-Null
                                            New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Server' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force | Out-Null
                                            New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Server' -Name 'Enabled' -Value '0' -Type DWord -Force | Out-Null
                                            New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Client' -Force | Out-Null
                                            New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Client' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force | Out-Null
                                            New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Client' -Name 'Enabled' -Value '0' -Type DWord -Force | Out-Null

                                            [string] $filePath = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), '.zip')
                                            
                                            if ($InfrastructureType -ieq 'Azure')
                                            {
                                                [string] $azurePsPackageName = 'Az'
                                                [string] $azurePsRequiredVersion = '13.0.0'

                                                [Microsoft.PackageManagement.Packaging.SoftwareIdentity] $packageInfo = Get-Package -Name $azurePsPackageName -ErrorAction SilentlyContinue

                                                if ($packageInfo -eq $null)
                                                {
                                                    Write-Host "Installing package ""$azurePsPackageName""..."
                                                    Install-Package -Name $azurePsPackageName -RequiredVersion $azurePsRequiredVersion -Force
                                                    Write-Host "Installing package ""$azurePsPackageName"" - DONE."
                                                    $packageInfo = Get-Package -Name $azurePsPackageName
                                                }

                                                Write-Host "$($packageInfo.Name) $($packageInfo.Version) is $($packageInfo.Status)"
                                                [PSCredential] $creds = [System.Management.Automation.PSCredential]::new($ClientId, (ConvertTo-SecureString $ClientSecret -AsPlainText -Force))

                                                Write-Host 'Establishing connection to Azure'
                                                Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId -Credential $creds -ServicePrincipal | Out-Null

                                                Write-Host "Connected to Azure..."

                                                Write-Host "Downloading ""$PackageFilePath"" to ""$filePath""."

                                                [psobject] $storageContext = $(Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName).Context
                                                [Hashtable] $fileDownloadArgs = @{
                                                    Container = $StorageContainerName
                                                    Context = $storageContext
                                                    Blob = $PackageFilePath
                                                    Destination = $filePath
                                                }

                                                Get-AzStorageBlobContent @fileDownloadArgs -Force

                                                Write-Host "Downloading ""$PackageFilePath"" to ""$filePath"" - DONE."

                                                Disable-AzContextAutosave -Scope Process | Out-Null
                                            }
                                            else 
                                            {
                                                Write-Host "Downloading ""$ArtifactsFileUrl"" to ""$filePath""."
                                                Invoke-WebRequest -UseBasicParsing -Verbose -Method Get -Uri $ArtifactsFileUrl -OutFile $filePath | Out-Null
                                            }
                                            

                                            if (Test-Path -LiteralPath $DevOpsDataRootDir)
                                            {
                                                Write-Host "Deleting ""$DevOpsDataRootDir""."
                                                Remove-Item -LiteralPath $DevOpsDataRootDir -Force -Recurse | Out-Null
                                            }

                                            Write-Host "Creating directory ""$DevOpsDataRootDir""."
                                            New-Item -Path $DevOpsDataRootDir -ItemType Directory -Force | Out-Null

                                            Write-Host "Extracting ZIP archive ""$filePath"" to directory ""$DevOpsDataRootDir""."
                                            Expand-Archive -LiteralPath $filePath -DestinationPath $DevOpsDataRootDir -Force | Out-Null

                                            Write-Host "Deleting file ""$filePath""."
                                            Remove-Item -Force -LiteralPath $filePath | Out-Null

                                            [string] $cloudFilesPath = "$DevOpsDataRootDir\.CloudFiles"

                                            $env:Path += ";$cloudFilesPath"
                                            [string] $machineEnvironmentPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Machine)
                                            [string] $newMachineLevelPath = $machineEnvironmentPath + ";$cloudFilesPath"
                                            [Environment]::SetEnvironmentVariable('Path', $newMachineLevelPath, [EnvironmentVariableTarget]::Machine)

                                            [string] $cloudUtilitiesScriptPath = "$cloudFilesPath\Soti.Utilities.Cloud.ps1"
                                                . $cloudUtilitiesScriptPath
                                            
                                            if ($InfrastructureType -ieq 'Azure')
                                            {
                                                Write-Host "Adding Private IP to FQDN mapping in host file for resource group ""$AzureVmResourceGroup"""
                                            
                                                Set-HostFileEntriesAzureVMs `
                                                    -ClientId $ClientId `
                                                    -ClientSecret $ClientSecret `
                                                    -SubscriptionId $SubscriptionId `
                                                    -TenantId $TenantId `
                                                    -ResourceGroup $AzureVmResourceGroup

                                                Write-Host "Adding Private IP to FQDN mapping in host file for resource group ""$AzureVmResourceGroup"" - DONE"
                                            }

                                            if (![object]::ReferenceEquals($OpenFirewallInboundPorts, $null) -and $OpenFirewallInboundPorts.Count -ne 0)
                                            {
                                                [string] $firewallRuleName = 'MobiControl Performance Tests environment - Inbound'
                                                Write-Host ''
                                                Write-Host "Creating Inbound firewall rule ""$firewallRuleName"" for TCP ports $($OpenFirewallInboundPorts -join ', ')."

                                                [string[]] $ports = $OpenFirewallInboundPorts | % { $_.ToString() }

                                                New-NetFirewallRule `
                                                    -Name $firewallRuleName `
                                                    -DisplayName $firewallRuleName `
                                                    -Direction Inbound `
                                                    -Action Allow `
                                                    -Protocol TCP `
                                                    -LocalPort $ports `
                                                    -Profile Any `
                                                    | Out-Null
                                            }

                                            if (![object]::ReferenceEquals($OpenFirewallOutboundPorts, $null) -and $OpenFirewallOutboundPorts.Count -ne 0)
                                            {
                                                [string] $firewallRuleName = 'MobiControl Performance Tests environment - Outbound'
                                                Write-Host ''
                                                Write-Host "Creating Outbound firewall rule ""$firewallRuleName"" for TCP ports $($OpenFirewallOutboundPorts -join ', ')."

                                                [string[]] $ports = $OpenFirewallOutboundPorts | % { $_.ToString() }

                                                New-NetFirewallRule `
                                                    -Name $firewallRuleName `
                                                    -DisplayName $firewallRuleName `
                                                    -Direction Outbound `
                                                    -Action Allow `
                                                    -Protocol TCP `
                                                    -LocalPort $ports `
                                                    -Profile Any `
                                                    | Out-Null
                                            }

                                            Write-Host ''
                                            [string] $trustedHostsValue = $TrustedHosts -join ','
                                            Write-Host "Adding the following value to the WinRM trusted hosts: ""$trustedHostsValue""."
                                            Set-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -Value $trustedHostsValue -Force -Concatenate | Out-Null

                                            Write-Host ''
                                            if ($InitializationScripts -isnot [object[]] -or $InitializationScripts.Count -eq 0)
                                            {
                                                Write-Host 'No initialization scripts defined.'
                                                return
                                            }

                                            [string] $nounSuffix = if ($InitializationScripts.Count -eq 1) { [string]::Empty } else { 's' }
                                            Write-Host "Executing $($InitializationScripts.Count) initialization script$nounSuffix."
                                            [psobject] $initializationScript = $null
                                            foreach ($initializationScript in $InitializationScripts)
                                            {
                                                [string] $initializationScriptName = $initializationScript.Name

                                                [string] $initializationScriptPath = `
                                                    [System.IO.Path]::GetFullPath("$DevOpsDataRootDir\.CloudFiles\$initializationScriptName.ps1")

                                                [hashtable] $initializationScriptArguments = @{}
                                                if (![object]::ReferenceEquals($initializationScript.Arguments, $null) `
                                                    -and $initializationScript.Arguments -is [psobject])
                                                {
                                                    $initializationScript.Arguments.PSObject.Properties `
                                                        | % { $initializationScriptArguments.Add($_.Name, $_.Value) }
                                                }

                                                Write-Host ''
                                                Write-Host "[Remote] Executing the initialization script ""$initializationScriptPath""."
                                                & $initializationScriptPath @initializationScriptArguments | Out-Host
                                            }

                                            Write-Host "Enabling crash dump"
                                            $MCServicesArray = @("MCDeplSvr.exe", "Soti.MobiControl.ManagementService.Host.exe", "elasticsearch-service-x64.exe")
                                            foreach ($serviceName in $MCServicesArray)
                                            {
                                                [string] $localDumpsRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$serviceName"
                                                New-Item -Path $localDumpsRegistryPath -Force | Out-Null
                                                New-ItemProperty -LiteralPath $localDumpsRegistryPath -Name 'DumpFolder' -Value 'C:\ProgramData\SOTI\MobiControl' -PropertyType ExpandString -Force | Out-Null
                                                New-ItemProperty -LiteralPath $localDumpsRegistryPath -Name 'DumpCount' -Value 10 -PropertyType DWord -Force | Out-Null
                                                New-ItemProperty -LiteralPath $localDumpsRegistryPath -Name 'DumpType' -Value 2 -PropertyType DWord -Force | Out-Null
                                                New-ItemProperty -LiteralPath $localDumpsRegistryPath -Name 'CustomDumpFlags' -Value 10 -PropertyType DWord -Force | Out-Null
                                            }
                                            #Renaming the computer to FQDN

                                            foreach ($property in $stackInfo | Get-Member -MemberType NoteProperty)
                                            {
                                                [string] $key = $property.Name
                                                [string] $value = $stackInfo.$key

                                                if (($key -match 'PublicIp\d*$') -and ($value -eq $InstanceAddress))
                                                {
                                                    [string] $newHostFqdn = $null

                                                    #Extracting the property name ex MSDeploymentServerPublicIp1 to MSDeploymentServer
                                                    [string] $cleanProperty = $key -replace 'PublicIp\d*$'
                                                    #Extracting the index
                                                    [string] $instanceIndex = $key -replace '\D'
                                                    [string] $cleanInstanceName = $cleanProperty + $instanceIndex
                                                    [string] $fqdnPropertyName = "${cleanProperty}PublicDnsName$instanceIndex"
                                                    [string] $newHostFqdn = $stackInfo.$fqdnPropertyName
                                                    [string] $hostName = $newHostFqdn.split('.')[0]
                                                    #Extracting the domain name ex soti.aws.com from hostName.soti.aws.com
                                                    [string] $domainName = $newHostFqdn -replace '^[^.]+\.?'

                                                    Write-Host "Renaming the host ""$cleanInstanceName"" with IP address: ""$InstanceAddress"" to ""$newHostFqdn"""
                                                    Rename-Computer -NewName $hostName -Force
                                                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Hostname" -Value $hostName
                                                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "NV Hostname" -Value "$hostName.$domainName"
                                                }
                                            }
                                        }
                            }
                            catch
                            {
                                $taskStatus = 'FAILED'
                                throw
                            }
                            finally
                            {
                                Write-Host "$taskTitle - $taskStatus (elapsed: $($stopwatch.Elapsed))."
                            }
                        }
            }

        [List[Job]] $activeJobList = [List[Job]]::new($jobs)
        while ($activeJobList.Count -ne 0)
        {
            [Job[]] $activeJobs = $activeJobList.ToArray()

            Write-Host "Waiting for the parallel jobs to complete (remaining: $($activeJobs.Count))."
            [Job] $finishedJob = Wait-Job -Any -Job $activeJobs -Timeout $waitJobTimeoutInSeconds
            if ($finishedJob -eq $null)
            {
                if ($commonStepsJobStopwatch.Elapsed -le $commonStepsTimeout)
                {
                    continue
                }

                [string] $jobNamesString = ($activeJobs | % { """$($_.Name)""" }) -join ', '

                Stop-Job -Job $activeJobs | Out-Null

                foreach ($job in $activeJobs)
                {
                    Write-MinorLogSeparator
                    Receive-Job -Job $job | Out-Host
                }

                Write-Host ''

                throw [TimeoutException]::new("The following jobs failed to complete within the allotted time ($commonStepsTimeout): $jobNamesString.")
            }

            $activeJobList.Remove($finishedJob) | Out-Null

            Write-MinorLogSeparator
            Receive-Job -Job $finishedJob | Out-Host
            Write-MinorLogSeparator

            if ($finishedJob.State -ne [JobState]::Completed)
            {
                [Object] $failureReason = if ($finishedJob.JobStateInfo -and $finishedJob.JobStateInfo.Reason)
                {
                    $finishedJob.JobStateInfo.Reason
                }
                elseif ($finishedJob.ChildJobs.Count -ne 0 -and $finishedJob.ChildJobs[0].JobStateInfo -and $finishedJob.ChildJobs[0].JobStateInfo.Reason)
                {
                    $finishedJob.ChildJobs[0].JobStateInfo.Reason
                }
                else
                {
                    $null
                }

                if ($failureReason -is [Exception])
                {
                    $failureReason = ([Exception]$failureReason).Message
                }

                if ([Object]::ReferenceEquals($failureReason, $null))
                {
                    $failureReason = '<UNKNOWN>'
                }

                throw "$($finishedJob.Name) - FAILED (job state: '$($finishedJob.State)'. Reason: $failureReason"
            }

            [PSDataCollection[ErrorRecord]] $finishedJobErrors = if ($finishedJob.Error.Count -ne 0)
            {
                $finishedJob.Error
            }
            elseif ($finishedJob.ChildJobs.Count -ne 0 -and $finishedJob.ChildJobs[0].Error.Count -ne 0)
            {
                $finishedJob.ChildJobs[0].Error
            }
            else
            {
                $null
            }

            if (![Object]::ReferenceEquals($finishedJobErrors, $null) -and $finishedJobErrors.Count -ne 0)
            {
                throw "$($finishedJob.Name) - FAILED (job state: '$($finishedJob.State)'. Reason: $finishedJobErrors"
            }
        }

        Restart-RemoteMachines

        Write-MinorLogSeparator
        Write-Host "Executing instance-specific setup steps for $($flattenedInstances.Count) instance$instanceNounSuffix."

        [int] $deviceFamilyIndex = 0

        foreach ($flattenedInstance in $flattenedInstances)
        {
            Write-MinorLogSeparator
            Write-Host "Executing instance-specific setup steps for $($flattenedInstance.Title)"

            [psobject] $scriptArguments = $flattenedInstance.ScriptArguments

            [hashtable] $convertedScriptArguments = @{}
            [string] $deviceFamily = $parsedDeviceFamilies[$deviceFamilyIndex]

            if ($flattenedInstance.Name -eq 'DeviceSimulator')
            {
                $convertedScriptArguments.Add('DeviceFamily', $deviceFamily) | Out-Null
                $deviceFamilyIndex++
                if ($deviceFamilyIndex -ge $parsedDeviceFamilies.Count)
                {
                    $deviceFamilyIndex = 0
                }
            }

            if (![object]::ReferenceEquals($scriptArguments, $null) -and ![object]::ReferenceEquals($scriptArguments.PSObject, $null))
            {
                $scriptArguments.PSObject.Properties `
                    | % `
                    {
                        [string] $propertyName = $_.Name
                        [object] $propertyValue = $_.Value

                        if ($propertyValue -is [psobject] -and $propertyValue.$cfOutputProperty -is [string])
                        {
                            [string] $cfOutputPropertyName = $propertyValue.$cfOutputProperty
                            $propertyValue = $stackInfo.PSObject.Properties.Where({ $_.Name -like $cfOutputPropertyName }).Value
                            Write-Verbose -Verbose "[Script Arguments] Injecting value ""$propertyName"" = ""$propertyValue"" from stack information ""$cfOutputPropertyName""."
                        }

                        $convertedScriptArguments.Add($propertyName, $propertyValue) | Out-Null
                    }
            }
            $convertedScriptArguments.Add('IPAddress', $flattenedInstance.Address) | Out-Null
            #$convertedScriptArguments.Add('InfrastructureType', $Arguments.InfrastructureType) | Out-Null

            try
            {
                [System.Diagnostics.Process] $rdpProcess = $null

                [System.Diagnostics.Process] $rdpProcess = Start-RdpProcess `
                    -ComputerName $flattenedInstance.Address `
                    -UserName $stackInfo.WindowsUserName `
                    -Password $stackInfo.WindowsPassword

                [psobject] $setupScriptResult = Execute-RemoteScript `
                    -Credential $remoteControlCredential `
                    -ComputerName $flattenedInstance.Address `
                    -ComputerTitle $flattenedInstance.Title `
                    -Path "$($Arguments.DevOpsDataRootDir)\.CloudFiles\SetUp-CloudInstance.$($flattenedInstance.Name).ps1" `
                    -Arguments $convertedScriptArguments
                    
                [string] $signalFilePath = "$($Arguments.DevOpsDataRootDir)\$([guid]::NewGuid().ToString('N')).signal"
                Write-Host ''
                Write-Host "Creating a signal file ""$SignalFilePath""."
                Set-Content -LiteralPath $SignalFilePath -Encoding UTF8 -Value ([string]::Empty) -Force | Out-Null
                <##Hack
                [int] $retryCount = 0
                while($retryCount -le 5)
                {
                    try
                    {
                        Execute-RemoteScript `
                            -Credential $remoteControlCredential `
                            -ComputerName $flattenedInstance.Address `
                            -ComputerTitle $flattenedInstance.Title `
                            -InDisconnectedSession `
                            -DisconnectedSessionSignalFilePath $signalFilePath `
                            -Arguments @{ DevOpsDataRootDir = $($Arguments.DevOpsDataRootDir); SignalFilePath = $signalFilePath; InfrastructureType = $($Arguments.InfrastructureType); AmdHostNames = $($Arguments.AmdHostNames) } `
                            -Path "$($Arguments.DevOpsDataRootDir)\.CloudFiles\Apply-RecommendedNetworkSettings.ps1"

                        break
                    }
                    catch
                    {
                        Write-Host "Exception coming again for Apply-RecommendedNetworkSettings.ps1 ....... (Retrying)"
                        $retryCount += 1
                        Start-Sleep -Seconds 30
                        if ($retryCount -ge 10)
                        {
                            throw
                        }
                    }
                }
                #Hack#>
                Write-Host ''
                Write-Host '*** SCRIPT RESULT:' -NoNewline
                if (Test-Null $setupScriptResult)
                {
                    Write-Host ' <None>'
                    continue
                }

                Write-Host ''
                $setupScriptResult | Format-Table | Out-Host
                Write-Host ''

                [hashtable] $extraCfOutput = $setupScriptResult.ExtraCfOutput -as [hashtable]
                if ($extraCfOutput -is [hashtable] -and $extraCfOutput.Count -ne 0)
                {
                    Write-Host ''
                    foreach ($entry in $extraCfOutput.GetEnumerator())
                    {
                        Write-Host "Adding extra stack information value: $($entry.Key) = $($entry.Value)"
                        $stackInfo | Add-Member -MemberType NoteProperty -Name $entry.Key -Value $entry.Value | Out-Null
                    }
                }
            }
            finally
            {
                if ($rdpProcess -ne $null)
                {
                    Write-Host "Closing the RDP connection with the VM ""$($flattenedInstance.Address)""."
                    $rdpProcess | Stop-Process -Force | Out-Null
                }
            }
        }

        $stackInfo | Print-StackInfo

        Write-Host ''
        Write-Host "Updating the stack information file ""$resolvedStackInfoFilePath""."
        $stackInfo | Set-StackInfoFileContent -LiteralPath $resolvedStackInfoFilePath

        Write-MinorLogSeparator

        Restart-RemoteMachines

        [string] $commonCloudScriptPath = [Path]::Combine($Arguments.DevOpsDataRootDir, '.CloudFiles', '.CloudScripts.Common.ps1')
        [string[]] $deploymentServerAddresses = $stackInfo | Get-ItemsFromStackInfo -PropertyPrefix 'DsPublicIp' -Verify

        foreach ($deploymentServerAddress in $deploymentServerAddresses)
        {
            Execute-RemoteScript `
                -Credential $remoteControlCredential `
                -ComputerName $deploymentServerAddress `
                -ComputerTitle 'Deployment Server VM' `
                -ArgumentList @($commonCloudScriptPath, $comPlusVariableForDS) `
                -ScriptBlock `
                    {
                        # NOTE: Since this script block is executed remotely, the fully qualified type names must be used here
                        param ([string] $commonCloudScriptPath, [bool] $comPlusVariableForDS)

                        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                        Microsoft.PowerShell.Core\Set-StrictMode -Version 1

                        #if($comPlusVariableForDS) //This is WA, it's implemented till the bugs are resovled in MC - as per discussion with Inder
                        if($true)
                        {
                            Write-Host "Setting Environment variables and registry changes for Simulator scalability on DS: $deploymentServerAddress"

                            [Environment]::SetEnvironmentVariable('COMPlus_SpinLimitConstant', '0x0', [EnvironmentVariableTarget]::Machine)
                            [Environment]::SetEnvironmentVariable('COMPlus_SpinLimitProcCap', '0x0', [EnvironmentVariableTarget]::Machine)
                            [Environment]::SetEnvironmentVariable('COMPlus_SpinLimitProcFactor', '0x0', [EnvironmentVariableTarget]::Machine)
    
                            Write-Host "DONE."
                        }
                        
                        [Environment]::SetEnvironmentVariable('GRPC_DNS_RESOLVER', 'native', [EnvironmentVariableTarget]::Machine)
                        Write-Host "DS Signal environment variables added."

                        . $commonCloudScriptPath

                        Start-ServiceSafely -Name 'MCDPSRV'
                    }
        }

        if($Arguments.SearchServiceDeploymentType -ieq 'standalone_vm')
        {
            # Verifying Soti search service status post restoration of snapshot
            Execute-RemoteScript `
                -Credential $remoteControlCredential `
                -ComputerName $stackInfo.SsPublicIp `
                -ComputerTitle 'Soti service server VM' `
                -ArgumentList @($commonCloudScriptPath, $Arguments.SearchServiceName) `
                -ScriptBlock `
                    {
                        # NOTE: Since this script block is executed remotely, the fully qualified type names must be used here
    
                        param ([string] $commonCloudScriptPath, [string] $searchServiceName)
    
                        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                        Microsoft.PowerShell.Core\Set-StrictMode -Version 1
    
                        . $commonCloudScriptPath
    
                        @($searchServiceName) | Start-ServiceSafely
                    }
        }
    
        Execute-RemoteScript `
            -Credential $remoteControlCredential `
            -ComputerName $stackInfo.MsPublicIp `
            -ComputerTitle 'Management Server VM' `
            -ArgumentList @($commonCloudScriptPath, $Arguments.SearchServiceName, $Arguments.SearchServiceDeploymentType) `
            -ScriptBlock `
                {
                    # NOTE: Since this script block is executed remotely, the fully qualified type names must be used here

                    param ([string] $commonCloudScriptPath, [string] $searchServiceName, [string] $searchServiceDeploymentType)

                    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
                    Microsoft.PowerShell.Core\Set-StrictMode -Version 1

                    Write-Host "Setting Environment variables and registry changes for scalability on MS"

                    [Environment]::SetEnvironmentVariable('COMPlus_SpinLimitConstant', '0x0', [EnvironmentVariableTarget]::Machine)
                    [Environment]::SetEnvironmentVariable('COMPlus_SpinLimitProcCap', '0x0', [EnvironmentVariableTarget]::Machine)
                    [Environment]::SetEnvironmentVariable('COMPlus_SpinLimitProcFactor', '0x0', [EnvironmentVariableTarget]::Machine)

                    Write-Host "DONE."

                    [Environment]::SetEnvironmentVariable('GRPC_DNS_RESOLVER', 'native', [EnvironmentVariableTarget]::Machine)
                    Write-Host "MS Signal environment variables added."

                    . $commonCloudScriptPath

                    [string] $managementServiceServiceName = 'MobiControl Management Service'
                    if($searchServiceDeploymentType -ieq 'ms_vm')
                    {
                        @($managementServiceServiceName, $searchServiceName) | Start-ServiceSafely
                    }
                    else 
                    {
                        @($managementServiceServiceName) | Start-ServiceSafely
                    }
                }
                
    }
    catch
    {
        [string] $errorDetails = Get-ErrorDetails
        Write-Host -ForegroundColor Red $errorDetails

        throw
    }
}

@Library('PowershellGet') _1
@Library('SotiPowerShell') _2

def GO_TO_DELETE_STAGE = false
def TEST_EXECUTION_FAILED = false
String LAST_FAILURE_STAGE = ""

import groovy.transform.Field

//Common constants
@Field
final String EncryptionKeyId = 'arn:aws:kms:us-east-1:134154494465:key/mrk-3b94243cf9e944fca005c55964cb26f8'

@Field
final String UpstreamNightlyTriggerJob = 'Trigger-NightlyPerfTestExecution'

@Field
final String AgentLabel = 'Ephemeral_BuildTools_Windows'

@Field
final String ArtifactsIn = 'AIn'

@Field
final String BuildVariablesFilePath = "${ArtifactsIn}/buildVariables.json"

@Field
Map buildVariables = null

@Field
Map installerBuildInfo = null

// TODO: Move this kind of configuration data to a Jenkins shared library (similar to https://ghe.soti.net/devops-jenkins-pipeline-libraries/SotiServicesConfigurationProvider)
@Field
final String VmPoolBaseUrl = 'http://vmpool.corp.soti.net:9200/pool-performance-onprem'

@Field
final String ArtifactoryRepository = 'MobiControl_PerformanceTesting'

@Field
final String PackageFileName = 'performance.zip'

@Field
final String ProductName = 'performancetesting' // TODO: Determine on the fly

@Field
final String AwsModuleMinimumVersion = '3.3.283.0'

@Field
final String TerraformMinimumVersion = '1.2.6'

@Field
final String TerraformThreads = '20'

@Field
final String ResourceGroup = 'rg-devops-prodext-useast'

@Field
final String AzureDataStorageResourceGroup = 'DefaultResourceGroup-EUS'

@Field
final String StorageAccountName = 'sotiazureautomation'

@Field
final String AzureDataContainerName = 'mc-performance-testing'

@Field
final String TerraformStateFileContainerName = 'statefiles'

@Field
final String StaticInputDataContainerName = 'inputdata'

@Field
final String StaticStorageBlob = 'performancetesting/static-data'

@Field
final String StandardBlobTier = 'Hot'

@Field
final String MobiControlManagementServiceInstanceCount = '1'

@Field
final String ApnsSimulatorInstanceCount = '1'

@Field
final String JMeterInstanceCount = '1'

@Field
final String SqlInstanceCount = '1'

@Field
final String DevOpsDataRootDir = 'C:/.devops'

@Field
final String TraceDBResultsDir = 'C:/Temp'

@Field
final String UploadFilesTempLocation = 'C:/S3UploadFiles'

@Field
final String InstanceDefinitionFileName = 'InfrastructureDefinition.json'

@Field
final String StackInfoFileNameOnly = 'StackInfo'

@Field
final String StackInfoFileExtension = '.json'

@Field
final String CloudJmeterScriptsDir = 'JMeterScripts'

@Field
final String CloudJmeterScriptsFileName = 'JMeterScripts.zip'

@Field
final String CloudTestDataDir = 'TestData'

@Field
final String CloudFileSyncDataFileName = 'FileSyncData.zip'

@Field
final String CloudJmeterPackagesFileName = 'JMeterPackages.zip'

@Field
final String VpcId = 'vpc-7229f90b'

@Field
final String IamProfile = 'DevOpsS3Tags-Role'

@Field
final String HqCidr1 = '199.243.131.34/32'

@Field
final String HqCidr2 = '207.167.194.100/32'

@Field
final String CaDataCentreCidr1 = '69.46.104.3/32'

@Field
final String CaDataCentreCidr2 = '65.93.254.226/32'

@Field
final String McInstallationId = '{C95C2B0C-9426-46C0-9567-FC0646BBC78B}'

@Field
final String CertificateThumbprint = '3535c27522384a90eadfffa8da952f0c607d6073'

@Field
final String PerformanceS3Bucket = 'performance-s3bucket'

@Field
final String PerformanceStaticDataS3Bucket = 'performance-s3bucket-static-data'

@Field
final String PerformanceStaticDataS3Repo = 'DataBaseBackUps'

@Field
final String PerformanceStaticDataAzureStorageAccount = 'sotimcperformancetest'

@Field
final String PerformanceStaticDataAzureContainer = 'databasebackups'

@Field
final String Ec2CpuCreditType = 'unlimited'

@Field
final String AwsRegion = 'us-east-1'

@Field
final String AzureLocation = 'eastus'

@Field
final String AwsKeyPairName = 'DevOpsAccountKey'

@Field
final String InfluxDbName = 'jmeterPerfDB'

@Field
final String LinuxUserName = 'adminuser'

@Field
final String WindowsUserName = 'Administrator'

@Field
final String AzureWindowsUserName = 'adminuser'

@Field
final String AzureDataDiskSkuType = 'PremiumV2_LRS'

@Field
final String AzureOsDiskSkuType = 'Premium_LRS'

@Field
final String MobiControlUserName = 'Administrator'

@Field
final String MobiControlDatabaseName = 'MobiControlDB'

@Field
final String MobiControlDatabaseArchiveName = 'MobiControlDB_Archive'

@Field
final String SqlServerUserName = 'sa'

@Field
final String ApnsChocolateyPackageId = 'apnssimulator'

@Field
final String ApnsRealDeviceCertificateFileName = 'APNS_RealDevice.pfx'

@Field
final String ApnsSimulatorCertificateFileName = 'APNS_Simulator.pfx'

@Field
final String EnvironmentConfigurationFileName = 'EnvironmentConfiguration.json'

@Field
final String SnapshotMappingFileNameOnly = "SnapshotMapping"

@Field
final String SnapshotMappingFileExtension = ".json"

@Field
final String PerformanceTestingMailingGroupId = 'Performance_Testing-CA@soti.net'

@Field
final String InfluxDbServer = 'influxdb-perf.soti.net'

@Field
final String InfluxDbToken = 'P06rUcI5_zGcF4KpWZOH07PkwAkvC7lnJ1X9WMv3OUQ5bCYlzsHnJkJjBQCU3deqmhvap7QqLDmlalcMJEhU0Q=='

@Field
final String CommonPsGetScriptsDefinition = 'Invoke-Tasks:[3.0.2],Invoke-DownloadFile:[1.0.0,1.9999.9999],Remove-OutdatedEc2Snapshots:[1.0.0,1.9999.9999],Soti.Utilities.Cloud:[1.0.0,1.9999.9999]'

@Field
final float ReconnectionTolerancePercentage = 0.5

@Field
final float EnrollmentTolerancePercentage = 0.05

@Field
final String SnapshotManagementTimeout = '04:00:00'

@Field
String MobiControlVersion = null

@Field
String InstallerBuildInfoFileName = 'Installer.BuildInfo.json'

@Field
String MobiControlBuildNumber = null

@Field
final Map AwsSecurityGroupsNames = [
    McPerformanceRdpTcp: 'mc_performance_rdp_tcp',
    McPerformanceRdpUdp: 'mc_performance_rdp_udp',
    McPerformanceSsh: 'mc_performance_ssh',
    McPerformanceWinrmAndGlobal: 'mc_performance_winrm_and_global',
    McPerformanceDb: 'mc_performance_db',
]

@Field
final Map TestExecutionPlatformToDeviceFamilyMap =
  [
    WindowsMobile: 2,
    WindowsModern: 8,
    AndroidPlus: 6,
    AndroidEnterprise: 6,
    iOS: 3,
    Mix: 0
  ]

@Field
final int CooldownThreshold = 20

@Field
String InstallerDir = null

@Field
String InstallerPath = null

@Field
String InstallerName = null

@Field
final String TestingDataFolderName = 'TestingData'

@Field
final String DistributedTestingDataFileName = 'distributed_env_testing.json'

@Field
final String SanityTestingDataFileName = 'sanity_testing.json'

@Field
final String ArtifactoryServerId = 'SOTI_PERF_ARTIFACTORY'

void fetchFromArtifactory(String sourcePath, String targetPath = '.')
{
    withJfCli
    {
        jf(['rt', 'dl', '--flat', '--detailed-summary', "--server-id=${ArtifactoryServerId}", sourcePath, targetPath])
    }
}

@Field
List<String> AmdHostNames = ['CAVMH105-AMD.corp.soti.net']

@Field
Map LdapDetails = [
    userName : 'insingh',
    userEmail:  'Inderjit.Singh@soti.net',
    department: 'Core Performance Team (Anu Chaddha)',
    country: 'CA',
    managerEmail: 'anu.chaddha@soti.net'
]

@Field
final String JENKINS_BUILD_URL = '__JENKINS_BUILD_URL__'

def getDateCreated() {
    def tz = TimeZone.getTimeZone('UTC')
    def dateFormat = new java.text.SimpleDateFormat('MM/dd/yyyy HH:mm Z')
    dateFormat.setTimeZone(tz)
    print("DateCreated: ${dateFormat.format(new Date())}")
    return "${dateFormat.format(new Date())}"
}

@Field
final String SanityTestingHtmlFilePath = 'TestExecutionResults/SanityEmailTestResultContent.html'

@Field
final String SanityTestingEmailSubject = 'Sanity Test results '

void checkAndSendSanityTestResultEmail(String recipient, String subject, String filePath, String buildUrl)
{
    boolean exists = fileExists(filePath)
    if(exists)
    {
        def body = readFile(filePath)
        body = body.replace(JENKINS_BUILD_URL, buildUrl)
        sendNotification(body, subject, recipient)
    }
    else
    {
        println("Sanity test results file not found ${filePath}")
    }
}

def getVaultSecrets()
{
    def secrets =
    [
        [
            path: 'secret/aws/gocd-service',
            engineVersion: 1,
            secretValues:
            [
                [envVar: 'AWS_ACCESS_KEY', vaultKey: 'access_key'],
                [envVar: 'AWS_SECRET_KEY', vaultKey: 'secret_key'],
                [envVar: 'AWS_ACCOUNT_NUMBER', vaultKey: 'account_id']
            ]
        ],
        [
            path: 'KVPv2/AzureCloudSecrets',
            engineVersion: 2,
            secretValues:
            [
                [envVar: 'ARM_CLIENT_ID', vaultKey: 'client_id'],
                [envVar: 'ARM_CLIENT_SECRET', vaultKey: 'client_secret'],
                [envVar: 'ARM_TENANT_ID', vaultKey: 'tenant_id'],
                [envVar: 'ARM_SUBSCRIPTION_ID', vaultKey: 'subscription_id']
            ]
        ],
        [
            path: 'KVPv2/MCPerformanceTests',
            engineVersion: 2,
            secretValues:
            [
                [envVar: 'DEFAULT_DATABASE_PASSWORD', vaultKey: 'DefaultDatabasePassword'],
                [envVar: 'VM_HOST_SERVICE_USER_NAME', vaultKey: 'VmHostServiceUserName'],
                [envVar: 'VM_HOST_SERVICE_USER_PASSWORD', vaultKey: 'VmHostServiceUserPassword']
            ]
        ],
        [
            path: 'secret/artifactory',
            engineVersion: 1,
            secretValues:
            [
                [envVar: 'ARTIFACTORY_ACCESS_TOKEN', vaultKey: 'serv_jenkins_api_key_perf_artifactory']
            ]
        ],
        [
            path: 'secret/vmpool',
            engineVersion: 1,
            secretValues:
            [
                [envVar: 'VMPOOL_AUTH_TOKEN', vaultKey: 'perf_auth_token']
            ]
        ],
        [
            path: 'secret/devops_encryption_certificate',
            engineVersion: 1,
            secretValues:
            [
                [envVar: 'DEVOPS_CERT_PASSWORD', vaultKey: 'password']
            ]
        ],
        [
            path: 'KVPv2/ServiceUserAccounts/Jenkins/LegacyServiceUser',
            engineVersion: 2,
            secretValues:
            [
                [envVar: 'SERV_JENKINS_USER', vaultKey: 'username'],
                [envVar: 'SERV_JENKINS_PASSWORD', vaultKey: 'password']
            ]
        ]
    ]
    return secrets
}

boolean isStageRestarted(String stageName)
{
    def restartCause = currentBuild.getBuildCauses().find \
        {
            cause -> cause._class == 'org.jenkinsci.plugins.pipeline.modeldefinition.causes.RestartDeclarativePipelineCause'
        }

    return restartCause != null && restartCause.shortDescription != null && restartCause.shortDescription.endsWith(", stage $stageName")
}

def escapeParameter(String value)
{
    return value.replaceAll('_', '\\\\_').replaceAll('\\*', '\\\\*')
}

def sendNotification(body, subject, recipient=null)
{
    if(isTriggeredByUpstreamJob(UpstreamNightlyTriggerJob))
    {
        subject = "[[${UpstreamNightlyTriggerJob}]] - ${subject}"
    }

    def mailRecipient = recipient ? recipient : buildVariables.EMAIL_NOTIFICATION_LIST

    emailext(body: body, mimeType: 'text/html', subject: subject, to: mailRecipient)
}

def alertUserForPipelineInput()
{   
    if (!isTriggeredByUpstreamJob(UpstreamNightlyTriggerJob))
    {
        def message = "The stage ${STAGE_NAME} has completed successfully and the pipeline is now waiting for your input. Please check the Jenkins job at ${BUILD_URL} to provide the necessary input."
        def subject = "$JOB_NAME/${currentBuild.number} : Status - Waiting for input at ${STAGE_NAME}"
        def recipient = LdapDetails.userEmail
        sendNotification(message, subject, recipient)
    }
}

boolean skipStageExecution()
{
    /*
        The default behavior is that `skipStageExecution` is false, meaning all stages will be executed. 
        However, if a stage is triggered by the timer based job and the stage value is set to false in the stages_to_execute section, it will be skipped.
        For example:
            "SetupStack": true - This will be executed.
            "ConfirmPrepareDeviceEnrollment": false - This will be skipped.
    */

    boolean skipStageExecution = false //Execute the stage
    if(isTriggeredByUpstreamJob(UpstreamNightlyTriggerJob)) 
    {
        if (buildVariables.containsKey(env.STAGE_NAME)) 
        {
            if(!buildVariables[env.STAGE_NAME])
            {
                skipStageExecution = true //skip the stage
            }
        }
    }
    return skipStageExecution
}

def internalInstallPowerShellGetScripts(psgScriptsDefinition)
{
    echo "Installing PowerShellGet scripts: ${psgScriptsDefinition}"
    InstallPowerShellGetScripts(
        psgScriptsDefinition,
        'SotiDevOps',
        'SOTI DevOps',
        "${env.SOTI_ARTIFACTORY_BASE_URL}/api/nuget/DevOps_PowerShell_Scripts",
        "${env.SOTI_ARTIFACTORY_BASE_URL}/api/nuget/DevOps_PowerShell_Modules",
        'Install-Script',
        null,
        'AllUsers')
}

void setBuildVariables(Map value)
{
    writeJSON json: value, pretty: 4, file: BuildVariablesFilePath
    this.buildVariables = value
}

Map getBuildVariables()
{
    if (this.buildVariables == null)
    {
        this.buildVariables = readJSON file: BuildVariablesFilePath
    }
    return this.buildVariables
}

def executeIndividualTasks(configurationFile, injectedVariablesString = null)
{
    copySourceCode('ciFolder.zip')
    def resolvedInjectedVariablesString = injectedVariablesString == null || injectedVariablesString.isEmpty() ? '@{}' : injectedVariablesString
    powershell \
        label: "PowerShell: Invoking Task \"${STAGE_NAME}\"",
        script:
            """
                Invoke-Tasks `
                    -Verbose `
                    -WorkspaceRoot '${WORKSPACE}' `
                    -ConfigurationFile '${configurationFile}' `
                    -ArtifactsIn '${ArtifactsIn}' `
                    -ArtifactsOut '${STAGE_NAME}' `
                    -VersionBuildNumber '${buildVariables.CURRENT_BUILD_NUMBER}' `
                    -RevisionId '${buildVariables.GIT_COMMIT_HASH}' `
                    -BranchName "${BRANCH_NAME}" `
                    -ExternalArgument @{} `
                    -InjectedVariables ${resolvedInjectedVariablesString}
            """
}

def executeMultiTasks(configurationFile, injectedVariablesString = null, includeTags = null)
{
    def resolvedInjectedVariablesString = injectedVariablesString == null || injectedVariablesString.isEmpty() ? '@{}' : injectedVariablesString
    powershell \
        label: "PowerShell: Invoking Task \"${STAGE_NAME}\"",
        script:
            """
                Invoke-Tasks `
                    -Verbose `
                    -WorkspaceRoot '${WORKSPACE}' `
                    -ConfigurationFile '${configurationFile}' `
                    -ArtifactsIn '${ArtifactsIn}' `
                    -ArtifactsOut '${STAGE_NAME}' `
                    -VersionBuildNumber '${buildVariables.CURRENT_BUILD_NUMBER}' `
                    -RevisionId '${buildVariables.GIT_COMMIT_HASH}' `
                    -BranchName "${BRANCH_NAME}" `
                    -IncludeTags ${serializeAsPowerShellObject(includeTags)} `
                    -ExternalArgument @{} `
                    -InjectedVariables ${resolvedInjectedVariablesString}
            """
}

def removeSnapshot(tagFilter, retentionPeriod)
{
    def parsedTagFilter = tagFilter.replace('_','-')
    powershell \
        label: "PowerShell: Remove Old Snapshot \"${STAGE_NAME}\"",
        script:
            """
                 Remove-OutdatedEc2Snapshots `
                    -AwsAccessKey '${AWS_ACCESS_KEY}' `
                    -AwsSecretKey '${AWS_SECRET_KEY}' `
                    -Region '${AwsRegion}' `
                    -TagFilter ${parsedTagFilter} `
                    -AwsAccountNumber '${AWS_ACCOUNT_NUMBER}' `
                    -RetentionPeriod '${retentionPeriod}'
            """
}

def getSubnetId()
{
    def subnetArray = ["subnet-2409d97e", "subnet-7e6cb752","subnet-7fb92f37", "subnet-a6c0acaa", "subnet-f16f5494"] as String[]
    if (params.INFRASTRUCTURE_TYPE == 'Azure')
    {
        String commonIdentifier = "/subscriptions/${env.ARM_SUBSCRIPTION_ID}/resourceGroups/rg-devops-prodext-useast/providers/Microsoft.Network/virtualNetworks/vnet-devops-ext-useast/subnets"
        subnetArray = [
            "${commonIdentifier}/subnet-devops-public-useast-02",
            "${commonIdentifier}/subnet-devops-public-useast-03"]
    }
    int buildNumber = "${BUILD_NUMBER}" as Integer
    return subnetArray[buildNumber % subnetArray.size()]
}

String getSecurityGroupId()
{
    return "/subscriptions/${env.ARM_SUBSCRIPTION_ID}/resourceGroups/rg-devops-prodext-useast/providers/Microsoft.Network/networkSecurityGroups/main_security_group"
}

String getRegion()
{
    return params.INFRASTRUCTURE_TYPE == 'Azure' ? AzureLocation : AwsRegion
}

String getUser()
{
    return params.INFRASTRUCTURE_TYPE == 'Azure' ? AzureWindowsUserName : WindowsUserName
}


def fetchArtifacts(String sourceStage, String sourcePath, String targetPath = null, Boolean optional = false)
{
    String filter = "${sourceStage}/${sourcePath}"
    echo "Copying artifacts (filter = \"${filter}\", target = \"${targetPath}\")."
    copyArtifacts(
        projectName: env.JOB_NAME,
        selector: specific(env.BUILD_NUMBER),
        fingerprintArtifacts: true,
        flatten: true,
        filter: filter,
        target: targetPath,
        optional: optional)
}

def copySourceCode(String archiveName)
{
    echo "Copying source code."

    copyArtifacts(
        projectName: env.JOB_NAME,
        selector: specific(env.BUILD_NUMBER),
        filter: "${archiveName}, ${BuildVariablesFilePath}",
        fingerprintArtifacts: true,
        flatten: false,
        target: env.WORKSPACE)

    unzip zipFile: archiveName, dir: "${ArtifactsIn}/.ci"
}

def publishReports(stageName, reportFiles, reportTitles)
{
    publishHTML(
        [
            allowMissing: true,
            alwaysLinkToLastBuild: false,
            keepAll: true,
            reportDir: "${stageName}",
            reportFiles: reportFiles,
            reportName: "Build Report - ${stageName}",
            reportTitles: reportTitles
        ])
}

def echoParameters()
{
    echo "CURRENT_OWNER_TAG: ${params.CURRENT_OWNER_TAG}"
    echo "TRIGGERED_BY: ${LdapDetails.userEmail}"
    echo "USER MANAGER: ${LdapDetails.managerEmail}"
    echo "MOBICONTROL_INSTALLER_URL: ${params.MOBICONTROL_INSTALLER_URL}"
    echo "DEVICE_FAMILIES: ${params.DEVICE_FAMILIES}"
    echo "DEVICE_COUNT_PER_SIMULATOR_VM: ${params.DEVICE_COUNT_PER_SIMULATOR_VM}"
    echo "NEW_SIMULATOR_URL: ${params.NEW_SIMULATOR_URL}"
    echo "TELEGRAF_SERVICE_URL: ${params.TELEGRAF_SERVICE_URL}"
    echo "MOBICONTROL_MS_INSTANCE_TYPE: ${params.MOBICONTROL_MS_INSTANCE_TYPE}"
    echo "MOBICONTROL_SS_INSTANCE_TYPE: ${params.MOBICONTROL_SS_INSTANCE_TYPE}"
    echo "MOBICONTROL_DS_INSTANCE_TYPE: ${params.MOBICONTROL_DS_INSTANCE_TYPE}"
    echo "JMETER_INSTANCE_TYPE: ${params.JMETER_INSTANCE_TYPE}"
    echo "SQL_SERVER_INSTANCE_TYPE: ${params.SQL_SERVER_INSTANCE_TYPE}"
    echo "SQL_INSTANCE_VOLUME_SIZE: ${params.SQL_INSTANCE_VOLUME_SIZE}"
    echo "JMETER_INSTANCE_VOLUME_SIZE: ${params.JMETER_INSTANCE_VOLUME_SIZE}"
    echo "DEVICE_SIMULATOR_INSTANCE_TYPE: ${params.DEVICE_SIMULATOR_INSTANCE_TYPE}"
    echo "XTHUB_INSTANCE_TYPE: ${params.XTHUB_INSTANCE_TYPE}"
    echo "APNS_SIMULATOR_INSTANCE_TYPE: ${params.APNS_SIMULATOR_INSTANCE_TYPE}"
    echo "DATA_INSERTION_SCENARIO: ${params.DATA_INSERTION_SCENARIO}"
    echo "DATA_INSERTION_SUITE_NAME: ${params.DATA_INSERTION_SUITE_NAME}"
    echo "TEST_EXECUTION_PLATFORM_NAME: ${params.TEST_EXECUTION_PLATFORM_NAME}"
    echo "TEST_EXECUTION_SUITE_NAME: ${params.TEST_EXECUTION_SUITE_NAME}"
    echo "TEST_EXECUTION_SCENARIO_NAME: ${params.TEST_EXECUTION_SCENARIO_NAME}"
    echo "TEST_EXECUTION_SCENARIO_SCRIPT_NAME: ${params.TEST_EXECUTION_SCENARIO_SCRIPT_NAME}"

    echo "UPSTREAM_SCENARIOS_TYPE: ${params.UPSTREAM_SCENARIOS_TYPE}"
    echo "UPSTREAM_TRIGGERED_BY: ${params.UPSTREAM_TRIGGERED_BY}"
    echo "UPSTREAM_MANUAL_STACK_DELETION: ${params.UPSTREAM_DELETE_STACK_MANUALLY}"
}

String queryLdap(String ldapSearchKey, String ldapQueryValue, String ldapQueryKey = 'sAMAccountName')
{
    withVault([vaultSecrets: getVaultSecrets()])
    {
        String value = sotiPowerShell \
            title: 'Get LDAP details',
            name: 'Find-LdapDetails',
            version: '1.0.0',
            returnOutput: true,
            arguments: \
                [
                    User: env.SERV_JENKINS_USER,
                    Password: env.SERV_JENKINS_PASSWORD,
                    LdapQueryKey: ldapQueryKey,
                    LdapQueryValue: ldapQueryValue,
                    LdapSearchKey: ldapSearchKey
                ]

        if('INPUT_ERROR_OR_KEY_NOT_FOUND'.equals(value))
        {
            throw new Exception("Not able to find ${ldapSearchKey} from LDAP for ${ldapQueryValue} using ${ldapQueryKey}. Please recheck input parameters and try again.")
        }

        println("queryLdap key:${ldapSearchKey} value: ${value}, using ${ldapQueryKey}")
        return value
    }
}

String getManagerEmail(String userName)
{
    String managerLdapObject = queryLdap('manager', userName)
    // We need to sanitize managerLdapObject = CN=manager name,OU=Users,OU=HQ,OU=CA,OU=SOTI,DC=corp,DC=soti,DC=net to get the "manager name".
    String managerSanitizedName = managerLdapObject.split(',')[0].split('=')[1] // Common name of the manager
    String managerLdapUserName = queryLdap('sAMAccountName', managerSanitizedName, 'cn') // Get the sAMAccountName of the manager

    return queryLdap('mail', managerLdapUserName)
}

void setLdapDetails()
{
    wrap([$class: 'BuildUser'])
    {
        if (!isTriggeredByUpstreamJobTimer(UpstreamNightlyTriggerJob))
        {
            String buildUserId = params.UPSTREAM_TRIGGERED_BY == 'TIMER' ? BUILD_USER_ID : params.UPSTREAM_TRIGGERED_BY

            this.LdapDetails.put('userName', queryLdap('sAMAccountName', buildUserId))
            this.LdapDetails.put('userEmail', queryLdap('mail', buildUserId))
            this.LdapDetails.put('department', queryLdap('department', buildUserId))
            this.LdapDetails.put('country', queryLdap('c', buildUserId))
            this.LdapDetails.put('managerEmail', getManagerEmail(buildUserId))
            println "LdapDetails ${this.LdapDetails}"
        }
    }
}

String formattedDepartmentString()
{
    String department = LdapDetails.department
    int indexOf = department.indexOf('(')

    return indexOf != -1 ? "(${department.substring(0, indexOf-1)})" : "(${department})"
}

String costUsageTag()
{
    return "MC_Performance_${LdapDetails.country}${formattedDepartmentString()}"
}

String consolidatedEmailNotificationList()
{
    return "${PerformanceTestingMailingGroupId}, ${LdapDetails.userEmail}"
}

boolean isTriggeredByUpstreamJob(String upstreamJobName)
{
    def upstreamCauses = currentBuild.getBuildCauses('org.jenkinsci.plugins.workflow.support.steps.build.BuildUpstreamCause')
    return upstreamJobName in upstreamCauses.upstreamProject
}

boolean isTriggeredByUpstreamJobTimer(String upstreamJobName)
{
    return isTriggeredByUpstreamJob(upstreamJobName) && params.UPSTREAM_TRIGGERED_BY == 'TIMER'
}

String fetchInstallerBuildUsed()
{   
    if(this.MobiControlVersion && this.MobiControlBuildNumber)
    {
        return 'v' + this.MobiControlVersion + '/' + this.MobiControlBuildNumber
    }
    else
    {
        println('Invalid Mobicontrol Version')
        return null
    }
    
}

boolean IsNextGenInstaller()
{
    if (this.MobiControlVersion)
    {
        (this.MobiControlVersion >= '2025.0.0') ? true : false
    }
    else
    {
        return false
    }
}

String getJmeterVersion() 
{
    return (this.MobiControlVersion ?: '0.0.0') >= '2025.1.0' ? '5.6.3005' : '4.0.1823433'
}

def fetchSourceCode()
{
    cleanWs()

    String searchServiceName = null
    String searchServiceDeploymentType = null
    String searchServiceInstanceCount = '0'

    switch (params.MC_SEARCH_TYPE)
    {
        case 'SotiSearch':
            searchServiceName = 'SOTISearch'
            searchServiceDeploymentType = 'ms_vm'
            break
        case 'SotiSearch-SeparateBox':
            searchServiceName = 'SOTISearch'
            searchServiceDeploymentType = 'standalone_vm'
            searchServiceInstanceCount = '1'
            break
        case 'ElasticSearch':
            searchServiceName = 'mobicontrolsearch-service'
            searchServiceDeploymentType = 'ms_vm'
            break
    }

    dir("${ArtifactsIn}/.ci")
    {
        commitDetails = checkout scm
    }
    def initialBuildVariables =
        [
            GIT_COMMIT_HASH: commitDetails.GIT_COMMIT,
            CURRENT_BUILD_NUMBER:  env.BUILD_NUMBER,
            SEARCH_SERVICE_NAME: searchServiceName,
            SEARCH_SERVICE_DEPLOYMENT_TYPE: searchServiceDeploymentType,
            SEARCH_SERVICE_INSTANCE_COUNT: searchServiceInstanceCount,
            COST_USAGE_TAG: "${isTriggeredByUpstreamJob(UpstreamNightlyTriggerJob) ? 'MC_Performance' : costUsageTag()}",
            CREATION_DATE_TAG: "${getDateCreated()}",
            EMAIL_NOTIFICATION_LIST: "${isTriggeredByUpstreamJob(UpstreamNightlyTriggerJob) ? PerformanceTestingMailingGroupId : consolidatedEmailNotificationList()}",
            ENABLE_SNAPSHOT_VOLUME_CREATION_RESTORATION: params.ENABLE_SNAPSHOT_VOLUME_CREATION_RESTORATION
        ]

    if(isTriggeredByUpstreamJob(UpstreamNightlyTriggerJob))
    {
        echo "Downloading data files from artifactory"
        fetchFromArtifactory("${ArtifactoryRepository}/${TestingDataFolderName}/${DistributedTestingDataFileName}", "${WORKSPACE}\\.infra\\dataset\\distributed_env_testing.json")
        fetchFromArtifactory("${ArtifactoryRepository}/${TestingDataFolderName}/${SanityTestingDataFileName}", "${WORKSPACE}\\.infra\\dataset\\sanity_testing.json")

        def json = readJSON file: "${ArtifactsIn}/.ci/.infra/dataset/scenarios_configuration_data.json"

        def filteredScenarios = json.scenarios.find { scenario ->  scenario.name == params.UPSTREAM_SCENARIOS_TYPE }

        Map stagestoExecute = filteredScenarios.stages_to_execute
        stagestoExecute.each { stageName, stageValue -> initialBuildVariables.put(stageName, stageValue) }
    }

    echo "Saving build context variables: ${initialBuildVariables}"
    setBuildVariables(initialBuildVariables) // Unable to use setter syntax due to this bug in Jenkins: https://issues.jenkins-ci.org/browse/JENKINS-45834

    archiveArtifacts artifacts: "${BuildVariablesFilePath}"
    zip zipFile: 'ciFolder.zip', archive: true, dir: "${ArtifactsIn}/.ci"
}

String getDeviceFamilyFromPipeline(String testExecutionPlatformName)
{
    String result = TestExecutionPlatformToDeviceFamilyMap[testExecutionPlatformName]
    if (!result)
    {
        throw new Exception("The device family mapping is not defined for \"${testExecutionPlatformName}\".")
    }
    return result
}

def fetchFilesFromArtifactory()
{
    String InstallerName = params.MOBICONTROL_INSTALLER_URL.split('/')[-1]
    powershell \
        label: 'Download files',
        script:
            """
                Invoke-DownloadFile `
                    -SourceUri '${params.MOBICONTROL_INSTALLER_URL}' `
                    -DestinationPath '${WORKSPACE}\\${ArtifactsIn}\\Setup\\${InstallerName}'
                Invoke-DownloadFile `
                    -SourceUri '${params.NEW_SIMULATOR_URL}' `
                    -DestinationPath '${WORKSPACE}\\${ArtifactsIn}\\NewSimulator.zip'
                Invoke-DownloadFile `
                    -SourceUri '${params.TELEGRAF_SERVICE_URL}' `
                    -DestinationPath '${WORKSPACE}\\${ArtifactsIn}\\TelegrafService.zip'
                Invoke-DownloadFile `
                    -SourceUri '${params.MOCK_SOTISERVICE_FILE_URL}' `
                    -DestinationPath '${WORKSPACE}\\${ArtifactsIn}\\MockSotiService.zip'
                Invoke-DownloadFile `
                    -SourceUri '${params.WINDOWS_MODERN_PACKAGE_URL}' `
                    -DestinationPath '${WORKSPACE}\\${ArtifactsIn}\\WindowsModernPackage.zip'
            """
}

def downloadInstallerBuildInfo(String buildInfoInstallerUrl, String jsonFilePath)
{
    sotiPowerShell \
        title: 'Download Installer.BuildInfo.json',
        command:
            """
                Invoke-DownloadFile `
                    -SourceUri '${buildInfoInstallerUrl}' `
                    -DestinationPath '${jsonFilePath}'
            """
}

def fetchInstallerBuildInfo()
{   
    // Removes the last segment from the installer url to get to the parent directory
    def baseUrl = params.MOBICONTROL_INSTALLER_URL.replaceAll(/\/[^\/]+$/, '/')
    def buildInfoInstallerUrl = "${baseUrl}${this.InstallerBuildInfoFileName}"
    def jsonFilePath = "${env.WORKSPACE}\\${ArtifactsIn}\\${this.InstallerBuildInfoFileName}"

    downloadInstallerBuildInfo(buildInfoInstallerUrl, jsonFilePath)
}

void setInstallerBuildInfo()
{   
    try {
        def jsonFileContent = readFile("${env.WORKSPACE}\\${ArtifactsIn}\\${this.InstallerBuildInfoFileName}")
        // Remove UTF-8 BOM encoding if it exists
        if (jsonFileContent.startsWith("\uFEFF")) {
            jsonFileContent = jsonFileContent.substring(1)
        }

        // Parse the JSON content
        this.installerBuildInfo = readJSON text: jsonFileContent

    } catch (Exception e) {
        error "Failed to read JSON: ${e.message}"
    }
}

String createUniqueBuildIdentifier()
{
    String randomId = UUID.randomUUID().toString()
    String buildUid = randomId.substring(0, 8)
    String buildFolder = "${env.BRANCH_NAME}-${currentBuild.number}-${buildUid}"
    return buildFolder
}

void createEnvironmentConfigurationFile(String packageFileUploadPath)
{
    def packageFileInfoVariables = [PackageFileUrl: packageFileUploadPath]
    writeJSON json: packageFileInfoVariables, pretty: 4, file: "${env.STAGE_NAME}/${EnvironmentConfigurationFileName}"
}

void getStackName()
{
    def envConfigurationInformation = readJSON(text: readFile("${env.STAGE_NAME}/${EnvironmentConfigurationFileName}").trim().replaceAll('^\uFEFF', ''))
    return envConfigurationInformation.StackName
}

void populateTestExecutionParameters(String platformName, String scenarioScriptName)
{
    def testExecutionParameters =
    [
        TEST_EXECUTION_PLATFORM_NAME: platformName,
        TEST_EXECUTION_SCENARIO_SCRIPT_NAME: scenarioScriptName
    ]
    return testExecutionParameters
}

Map determineInfrastructureDefinition()
{
    Map instanceTypes = [:]
    Map imagesUsed = [:]
    def infrastructureDefinitionMapping = readJSON file: "${ArtifactsIn}/.ci/SetupStage/Misc/${InstanceDefinitionFileName}"

    switch (params.INFRASTRUCTURE_TYPE)
    {
        case 'Azure':
            instanceTypes =
            [
                APNS_SIMULATOR_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".APNS."${params.APNS_SIMULATOR_INSTANCE_TYPE}".'Azure-Equivalent',
                DEVICE_SIMULATOR_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.DEVICE_SIMULATOR_INSTANCE_TYPE}".'Azure-Equivalent',
                JMETER_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.JMETER_INSTANCE_TYPE}".'Azure-Equivalent',
                MOBICONTROL_DS_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.MOBICONTROL_DS_INSTANCE_TYPE}".'Azure-Equivalent',
                MOBICONTROL_MS_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.MOBICONTROL_MS_INSTANCE_TYPE}".'Azure-Equivalent',
                MOBICONTROL_SS_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.MOBICONTROL_SS_INSTANCE_TYPE}".'Azure-Equivalent',
                SQL_SERVER_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.SQL_SERVER_INSTANCE_TYPE}".'Azure-Equivalent',
                XTHUB_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.XTHUB_INSTANCE_TYPE}".'Azure-Equivalent'
            ]
            imagesUsed =
            [
                SQL_IMAGE: infrastructureDefinitionMapping.ImageDefinition."${params.INFRASTRUCTURE_TYPE}"."${params.WINDOWS_OS_VERSION}"."${params.SQL_VERSION}".ImageDescriptor,
                MC_IMAGE: infrastructureDefinitionMapping.ImageDefinition."${params.INFRASTRUCTURE_TYPE}"."${params.WINDOWS_OS_VERSION}".General.ImageDescriptor,
                XTHUB_IMAGE: ''
            ]
            break
        case 'AWS':
            instanceTypes =
            [
                APNS_SIMULATOR_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".APNS."${params.APNS_SIMULATOR_INSTANCE_TYPE}".'EC2-Equivalent',
                DEVICE_SIMULATOR_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.DEVICE_SIMULATOR_INSTANCE_TYPE}".'EC2-Equivalent',
                JMETER_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.JMETER_INSTANCE_TYPE}".'EC2-Equivalent',
                MOBICONTROL_DS_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.MOBICONTROL_DS_INSTANCE_TYPE}".'EC2-Equivalent',
                MOBICONTROL_MS_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.MOBICONTROL_MS_INSTANCE_TYPE}".'EC2-Equivalent',
                MOBICONTROL_SS_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.MOBICONTROL_SS_INSTANCE_TYPE}".'EC2-Equivalent',
                SQL_SERVER_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.SQL_SERVER_INSTANCE_TYPE}".'EC2-Equivalent',
                XTHUB_INSTANCE_TYPE: infrastructureDefinitionMapping.InstanceType."${params.INFRASTRUCTURE_TYPE}".General."${params.XTHUB_INSTANCE_TYPE}".'EC2-Equivalent'
            ]
            imagesUsed =
            [
                SQL_IMAGE: infrastructureDefinitionMapping.ImageDefinition."${params.INFRASTRUCTURE_TYPE}"."${params.WINDOWS_OS_VERSION}"."${params.SQL_VERSION}".ImageDescriptor,
                MC_IMAGE: infrastructureDefinitionMapping.ImageDefinition."${params.INFRASTRUCTURE_TYPE}"."${params.WINDOWS_OS_VERSION}".General.ImageDescriptor,
                XTHUB_IMAGE: infrastructureDefinitionMapping.ImageDefinition."${params.INFRASTRUCTURE_TYPE}".Linux.ImageDescriptor
            ]
            break
        case 'Local':
            instanceTypes =
            [
                APNS_SIMULATOR_INSTANCE_TYPE: params.APNS_SIMULATOR_INSTANCE_TYPE,
                DEVICE_SIMULATOR_INSTANCE_TYPE: params.DEVICE_SIMULATOR_INSTANCE_TYPE,
                JMETER_INSTANCE_TYPE: params.JMETER_INSTANCE_TYPE,
                MOBICONTROL_DS_INSTANCE_TYPE: params.MOBICONTROL_DS_INSTANCE_TYPE,
                MOBICONTROL_MS_INSTANCE_TYPE: params.MOBICONTROL_MS_INSTANCE_TYPE,
                MOBICONTROL_SS_INSTANCE_TYPE: params.MOBICONTROL_SS_INSTANCE_TYPE,
                SQL_SERVER_INSTANCE_TYPE: params.SQL_SERVER_INSTANCE_TYPE,
                XTHUB_INSTANCE_TYPE: params.XTHUB_INSTANCE_TYPE
            ]
            imagesUsed =
            [
                SQL_IMAGE: infrastructureDefinitionMapping.ImageDefinition."${params.INFRASTRUCTURE_TYPE}"."${params.WINDOWS_OS_VERSION}"."${params.SQL_VERSION}".ImageDescriptor,
                MC_IMAGE: infrastructureDefinitionMapping.ImageDefinition."${params.INFRASTRUCTURE_TYPE}"."${params.WINDOWS_OS_VERSION}".General.ImageDescriptor,
                XTHUB_IMAGE: infrastructureDefinitionMapping.ImageDefinition."${params.INFRASTRUCTURE_TYPE}".Linux.ImageDescriptor
            ]
            break
        default:
            throw new Exception("Unexpected infrastructure type: ${params.INFRASTRUCTURE_TYPE}")
    }
    return [instanceTypes: instanceTypes, imagesUsed: imagesUsed]
}

void createLink(String imageLink, String linkUrl, String linkText)
{
    createSummary(imageLink).appendText("<a href=\"${org.apache.commons.lang.StringEscapeUtils.escapeHtml(linkUrl)}\">${org.apache.commons.lang.StringEscapeUtils.escapeHtml(linkText)}</a>")
    manager.addBadge(imageLink, linkText, linkUrl)
}

void createPublishedArtifactsLink()
{
    String buildArtifactsLink = null
    switch (params.INFRASTRUCTURE_TYPE)
    {
        case 'AWS':
            buildArtifactsLink = "https://s3.console.aws.amazon.com/s3/buckets/${PerformanceS3Bucket}?region=${AwsRegion}&prefix=BuildArtifacts/${JOB_NAME}/${BUILD_NUMBER}/&showversions=false"
            break
        case 'Local':
            buildArtifactsLink = "${PERF_ARTIFACTORY_BASE_URL}/${ArtifactoryRepository}/BuildArtifacts/${JOB_NAME}/${BUILD_NUMBER}"
            createLink(
                '/images/artifactory.png',
                "${buildArtifactsLink}",
                'Build Artifacts -> Artifactory Link')
            break
        case 'Azure':
            break
        default:
            throw new Exception("Unexpected infrastructure type: ${params.INFRASTRUCTURE_TYPE}")
    }
    return buildArtifactsLink
}

void copyFiles(String sourcePath, String destinationPath)
{
    fileOperations([fileCopyOperation(includes: sourcePath, targetLocation: destinationPath, flattenFiles: true)])
}

void setupStack()
{
    Map infrastructureDefinitionMap = determineInfrastructureDefinition()
    Map instanceTypes = infrastructureDefinitionMap.instanceTypes
    Map imagesToBeUsed = infrastructureDefinitionMap.imagesUsed

    McInstallationId = params.REGISTRATION_CODE ? "{${UUID.randomUUID()}}" : McInstallationId

    print "McInstallationId was computed as: ${McInstallationId}"

    fetchArtifacts('PrepareEnvSetup', EnvironmentConfigurationFileName, "${WORKSPACE}/${ArtifactsIn}")

    String jmeterScriptBranch = params.JMETER_SCRIPTS_BRANCH ? params.JMETER_SCRIPTS_BRANCH : 'master'

    withVault([vaultSecrets: getVaultSecrets()])
    {
        def setupStackInjectedVariables =
            """@{
                    InfrastructureType = '${params.INFRASTRUCTURE_TYPE}'
                    MobiControlFunctionalityType = '${params.MC_FUNCTIONALITY_TYPE}'
                    Pipeline = '${ProductName}'
                    VmPoolBaseUrl = '${VmPoolBaseUrl}'
                    VmPoolAuthToken = '${VMPOOL_AUTH_TOKEN}'
                    DevOpsDataRootDir = '${DevOpsDataRootDir}'
                    DevOpsCertPassword = '${DEVOPS_CERT_PASSWORD}'
                    Bucket = '${PerformanceS3Bucket}'
                    StaticDataBucket = '${PerformanceStaticDataS3Bucket}'
                    FileSyncDataLocation = "${IsNextGenInstaller() ? 'C:/MobiControl/FileSyncData' : 'C:/FileSyncData'}"
                    CloudJmeterScriptsDir = "${CloudJmeterScriptsDir}/${jmeterScriptBranch}"
                    CloudJmeterScriptsFileName = '${CloudJmeterScriptsFileName}'
                    CloudTestDataDir = '${CloudTestDataDir}'
                    CloudFileSyncDataFileName = '${CloudFileSyncDataFileName}'
                    CloudJmeterPackagesFileName = '${CloudJmeterPackagesFileName}'
                    Region = '${getRegion()}'
                    AccessKey = '${AWS_ACCESS_KEY}'
                    SecretKey = '${AWS_SECRET_KEY}'
                    TerraformWorkingDirectory = "${WORKSPACE}/${ArtifactsIn}/.ci/.infra/terraform/${params.INFRASTRUCTURE_TYPE}"
                    TerraformThreads = '${TerraformThreads}'
                    InstanceDefinitionFileName = '${InstanceDefinitionFileName}'
                    InstallerUrl = '${params.MOBICONTROL_INSTALLER_URL}'
                    DeviceFamilies = '${params.DEVICE_FAMILIES}'
                    LocalStackCreationTimeout = '${LOCAL_STACK_CREATION_TIMEOUT}'
                    AwsStackCreationTimeout = '${CF_TIMEOUT_IN_MINUTES}'
                    KeyPair = '${AwsKeyPairName}'
                    DefaultDatabasePassword = '${DEFAULT_DATABASE_PASSWORD}'
                    LinuxUserName = '${LinuxUserName}'
                    SqlServerUserName = '${SqlServerUserName}'
                    WindowsUserName = '${getUser()}'
                    MobiControlUserName = '${MobiControlUserName}'
                    MobiControlDatabaseName = '${MobiControlDatabaseName}'
                    MobiControlDatabaseArchiveName = '${MobiControlDatabaseArchiveName}'
                    MobiControlManagementServiceInstanceType = '${instanceTypes.MOBICONTROL_MS_INSTANCE_TYPE}'
                    SearchServiceInstanceType = '${instanceTypes.MOBICONTROL_SS_INSTANCE_TYPE}'
                    MobiControlDeploymentServerInstanceType = '${instanceTypes.MOBICONTROL_DS_INSTANCE_TYPE}'
                    JMeterInstanceType = '${instanceTypes.JMETER_INSTANCE_TYPE}'
                    SqlInstanceType = '${instanceTypes.SQL_SERVER_INSTANCE_TYPE}'
                    SqlVersion = '${params.SQL_VERSION}'
                    DeviceSimulatorInstanceType = '${instanceTypes.DEVICE_SIMULATOR_INSTANCE_TYPE}'
                    XTHubInstanceType = '${instanceTypes.XTHUB_INSTANCE_TYPE}'
                    ApnsSimulatorInstanceType = '${instanceTypes.APNS_SIMULATOR_INSTANCE_TYPE}'
                    MobiControlManagementServiceInstanceCount = '${MobiControlManagementServiceInstanceCount}'
                    SqlInstanceCount = '${SqlInstanceCount}'
                    JMeterInstanceCount = '${JMeterInstanceCount}'
                    ApnsSimulatorInstanceCount = '${ApnsSimulatorInstanceCount}'
                    MobiControlDeploymentServerInstanceCount = '${params.DS_MACHINE_COUNT}'
                    DeviceSimulatorInstanceCount = '${params.DEVICE_SIMULATOR_MACHINE_COUNT}'
                    XTHubInstanceCount = '${params.XTHUB_MACHINE_COUNT}'
                    RemoteAccessCidr1 = '${HqCidr1}'
                    RemoteAccessCidr2 = '${HqCidr2}'
                    RemoteControlCidr1 = '${CaDataCentreCidr1}'
                    RemoteControlCidr2 = '${CaDataCentreCidr2}'
                    MCImage = '${imagesToBeUsed.MC_IMAGE}'
                    SqlImage = '${imagesToBeUsed.SQL_IMAGE}'
                    XTHubImage = '${imagesToBeUsed.XTHUB_IMAGE}'
                    AwsMinimumVersion = '${AwsModuleMinimumVersion}'
                    TerraformMinimumVersion = '${TerraformMinimumVersion}'
                    VpcId = '${VpcId}'
                    SubnetId = '${getSubnetId()}'
                    InstanceCpuCreditType = '${Ec2CpuCreditType}'
                    IamProfile = '${IamProfile}'
                    StackInfoFilePath = '\$Out:${StackInfoFileNameOnly}${StackInfoFileExtension}'
                    ConfigurationFilePath = '\$In:${EnvironmentConfigurationFileName}'
                    CurrentOwnerTag = '${params.CURRENT_OWNER_TAG}'
                    TriggeredByTag = '${LdapDetails.userEmail}'
                    ManagerEmailTag = '${LdapDetails.managerEmail}'
                    RegistrationCode = '${params.REGISTRATION_CODE}'
                    McInstallationId = '${McInstallationId}'
                    ApnsChocolateyPackageId = '${ApnsChocolateyPackageId}'
                    ClientId = '${ARM_CLIENT_ID}'
                    ClientSecret = '${ARM_CLIENT_SECRET}'
                    TenantId = '${ARM_TENANT_ID}'
                    SubscriptionId = '${ARM_SUBSCRIPTION_ID}'
                    ResourceGroup = '${ResourceGroup}'
                    StorageAccountName = '${StorageAccountName}'
                    TerraformStateFileContainerName = '${TerraformStateFileContainerName}'
                    StaticInputDataContainerName = '${StaticInputDataContainerName}'
                    StandardBlobTier = '${StandardBlobTier}'
                    StaticStorageBlob = '${StaticStorageBlob}'
                    AzureSecurityGroupId = '${getSecurityGroupId()}'
                    AwsMcPerformanceRdpTcpSecurityGroupName = '${AwsSecurityGroupsNames.McPerformanceRdpTcp}'
                    AwsMcPerformanceRdpUdpSecurityGroupName = '${AwsSecurityGroupsNames.McPerformanceRdpUdp}'
                    AwsMcPerformanceSshSecurityGroupName = '${AwsSecurityGroupsNames.McPerformanceSsh}'
                    AwsMcPerformanceWinrmAndGlobalSecurityGroupName = '${AwsSecurityGroupsNames.McPerformanceWinrmAndGlobal}'
                    AwsMcPerformanceDbSecurityGroupName = '${AwsSecurityGroupsNames.McPerformanceDb}'
                    SearchServiceName = '${buildVariables.SEARCH_SERVICE_NAME}'
                    SearchServiceDeploymentType = '${buildVariables.SEARCH_SERVICE_DEPLOYMENT_TYPE}'
                    SearchServiceInstanceCount = '${buildVariables.SEARCH_SERVICE_INSTANCE_COUNT}'
                    DataBaseSetupType = '${params.DATABASE_SETUP}'
                    TestExecutionSuiteName = '${params.TEST_EXECUTION_SUITE_NAME}'
                    DataBaseBackUpFileVersion = '${params.RESTORE_DATABASE_VERSION}'
                    DataBaseDescription = '${params.RESTORE_DATABASE_DESCRIPTION}'
                    SqlInstanceVolumeSize = '${params.SQL_INSTANCE_VOLUME_SIZE}'
                    AzureSqlInstanceDataDiskSkuType = '${AzureDataDiskSkuType}'
                    AzureInstanceDataDiskSkuType = '${AzureDataDiskSkuType}'
                    AzureSqlOsDiskSkuType = '${AzureOsDiskSkuType}'
                    AzureOsDiskSkuType = '${AzureOsDiskSkuType}'
                    JMeterInstanceVolumeSize = '${params.JMETER_INSTANCE_VOLUME_SIZE}'
                    CostUsageTag = '${buildVariables.COST_USAGE_TAG}'
                    CreationDateTag = '${buildVariables.CREATION_DATE_TAG}'
                    VmHostServiceUserName = '${VM_HOST_SERVICE_USER_NAME}'
                    VmHostServiceUserPassword = '${VM_HOST_SERVICE_USER_PASSWORD}'
                    IsNextGenInstaller = '${IsNextGenInstaller()}'
                    EncryptionKeyId = '${EncryptionKeyId}'
                    AzureDataStorageResourceGroup = '${AzureDataStorageResourceGroup}'
                    AzureStaticDataStorageAccountName = '${PerformanceStaticDataAzureStorageAccount}'
                    AzureStaticDataContainerName = '${PerformanceStaticDataAzureContainer}'
                    AmdHostNames = '${AmdHostNames}'
                }
            """

        executeMultiTasks(BUILDCONFIG_FILE_PATH, setupStackInjectedVariables)
    }
}

void isRestartAllowed(boolean isRestarted)
{
    if (isRestarted && !buildVariables.ENABLE_SNAPSHOT_VOLUME_CREATION_RESTORATION)
    {
        throw new Exception('Restart is not permitted because the snapshot creation was not enabled in the original environment creation. \nEither rebuild the original build OR start a new build with desired parameters set.')
    }
}

List<String> determineTags(boolean isRestarted, String infrastructureType)
{
    List<String> tags = ['common']
    if(buildVariables.ENABLE_SNAPSHOT_VOLUME_CREATION_RESTORATION)
    {
        tags.add('RestoreSnapshot')
        if (!isRestarted)
        {
            tags.add('CreateSnapshot')
            if (!infrastructureType.equals('Azure'))
            {
                tags.add('CopySnapshotMappingFile')
            }
        }
    }
    return tags
}

void setBuildDescription()
{
    currentBuild.description = "* Infrastructure Type: **${escapeParameter(params.INFRASTRUCTURE_TYPE)}**  \n" +
        "* Windows OS version: **${escapeParameter(params.WINDOWS_OS_VERSION)}**  \n" +
        "* Build Used: **${fetchInstallerBuildUsed()}** \n" +
        "* Stack Name: **${getStackName()}**  \n" + 
        "* Device Count: **${escapeParameter(params.DEVICE_COUNT_PER_SIMULATOR_VM)}** devices per simulator VM \n" +
        "* Device Family: **${escapeParameter(params.DEVICE_FAMILIES)}** \n" + 
        "* Owner: **${escapeParameter(params.CURRENT_OWNER_TAG)}** \n" +
        "* Scenario Type: **${escapeParameter(params.MC_FUNCTIONALITY_TYPE)}** \n" + 
        "* Search Type: **${escapeParameter(params.MC_SEARCH_TYPE)}** \n" + 
        "* Environment Device Scale: **${escapeParameter(params.ENVIRONMENT_DEVICE_SCALE)}** \n" +
        "* DataBase Type: **${escapeParameter(params.DATABASE_SETUP)}** \n" + 
        "* Test Execution Suite Name: **${escapeParameter(params.TEST_EXECUTION_SUITE_NAME)}**"
}

void setMobiControlVersion()
{   
    def versionParts = this.installerBuildInfo.BuildInfo.Version.split('\\.')
    if (versionParts.length >= 3) 
    {
        this.MobiControlVersion = versionParts[0..2].join('.')
        this.MobiControlBuildNumber = versionParts[3]
        println("MobiControl Version: ${this.MobiControlVersion}")
        println("MobiControl Build Number: ${this.MobiControlBuildNumber}")
    } else {
        println("No valid version found.")
    }
}

void setMCBuildDetails()
{
    fetchInstallerBuildInfo()
    setInstallerBuildInfo()
    setMobiControlVersion()
}

void prepareEnvSetup()
{
    setLdapDetails()
    echoParameters()
    fetchSourceCode()
    echo "Installing dependency scripts."
    internalInstallPowerShellGetScripts(CommonPsGetScriptsDefinition)
    fetchFilesFromArtifactory()
    setMCBuildDetails()
    withVault([vaultSecrets: getVaultSecrets()])
    {
        def packagingInjectedVariables =
            """@{
                    InfrastructureType = '${params.INFRASTRUCTURE_TYPE}'
                    Pipeline = '${ProductName}'
                    Bucket = '${PerformanceS3Bucket}'
                    Region = '${getRegion()}'
                    AccessKey = '${AWS_ACCESS_KEY}'
                    SecretKey = '${AWS_SECRET_KEY}'
                    ArtifactoryUrl = '${PERF_ARTIFACTORY_BASE_URL}'
                    ArtifactoryRepository = '${ArtifactoryRepository}'
                    ArtifactoryAccessToken = '${ARTIFACTORY_ACCESS_TOKEN}'
                    PackageFileName = '${PackageFileName}';
                    OutputConfigurationFilePath = '\$Out:${EnvironmentConfigurationFileName}'
                    ApnsChocolateyPackageId = '${ApnsChocolateyPackageId}'
                    ClientId = '${ARM_CLIENT_ID}'
                    ClientSecret = '${ARM_CLIENT_SECRET}'
                    TenantId = '${ARM_TENANT_ID}'
                    SubscriptionId = '${ARM_SUBSCRIPTION_ID}'
                    ResourceGroup = '${ResourceGroup}'
                    StorageAccountName = '${StorageAccountName}'
                    ContainerName = '${AzureDataContainerName}'
                    StandardBlobTier = '${StandardBlobTier}'
                    IosConsoleRunnerVersion ='${params.IOS_CONSOLE_RUNNER_VERSION}'
                    JMeterVersion= '${getJmeterVersion()}'
                }
            """
        def includeTags = [params.INFRASTRUCTURE_TYPE]
        executeMultiTasks(BUILDCONFIG_FILE_PATH, packagingInjectedVariables, includeTags)
    }
}

void prepareDeviceEnrollment()
{
    cleanWs()
    echo "Installing dependency scripts."
    internalInstallPowerShellGetScripts(CommonPsGetScriptsDefinition)
    setMCBuildDetails()
    fetchArtifacts('SetupStack', "${StackInfoFileNameOnly}${StackInfoFileExtension}", "${WORKSPACE}/${ArtifactsIn}")
    withVault([vaultSecrets: getVaultSecrets()])
    {
        def prepareDeviceEnrollmentInjectedVariables =
            """@{
                    InfrastructureType = '${params.INFRASTRUCTURE_TYPE}'
                    DevOpsDataRootDir = '${DevOpsDataRootDir}'
                    StackInfoFilePath = '\$In:${StackInfoFileNameOnly}${StackInfoFileExtension}'
                    CurrentOwnerTag = '${params.CURRENT_OWNER_TAG}'
                    DataBaseSetupType = '${params.DATABASE_SETUP}'
                    TestExecutionSuiteName = '${params.TEST_EXECUTION_SUITE_NAME}'
                    CooldownThreshold = '${CooldownThreshold}'
                    InfluxDbServer = '${InfluxDbServer}'
                    InfluxDbToken = '${InfluxDbToken}'
                    InfluxDbName = '${InfluxDbName}'
                    StaticDataBucket = '${PerformanceStaticDataS3Bucket}'
                    SqlServerUserName = '${SqlServerUserName}'
                    DeviceCountPerSimulatorVM = '${params.DEVICE_COUNT_PER_SIMULATOR_VM}'
                    EnrollmentDeviceFamilies = '${params.DEVICE_FAMILIES}'
                    WindowsUserName = '${WindowsUserName}'
                    MobiControlUserName = '${MobiControlUserName}'
                    ApnsChocolateyPackageId = '${ApnsChocolateyPackageId}'
                    ApnsRealDeviceCertificateFileName = '${ApnsRealDeviceCertificateFileName}'
                    ApnsSimulatorCertificateFileName = '${ApnsSimulatorCertificateFileName}'
                    EnableDDM = '${params.ENABLE_DDM}'
                    IsNextGenInstaller = '${IsNextGenInstaller()}'
                }
            """
        executeIndividualTasks(BUILDCONFIG_FILE_PATH, prepareDeviceEnrollmentInjectedVariables)
    }
}

List getParameterList()
{
    return [
        choice(
            name: 'INFRASTRUCTURE_TYPE',
            choices: ['Azure', 'AWS', 'Local'],
            description: 'The infrastructure setup location.\n\n---\n\n'),

        choice(
            name: 'WINDOWS_OS_VERSION',
            choices: ['WS2022', 'WS2025'],
            description: 'Select Windows OS version.\n\n---\n\n'),

        choice(
            name: 'ENVIRONMENT_DEVICE_SCALE',
            choices: ['100K', '100K-IOS', '500K', '1M', 'Sanity/Staging', 'Custom'],
            description: 'The environment device scale.\n\n---\n\n'),

        choice(
            name: 'DATABASE_SETUP',
            choices: ['Clean', 'Restore'],
            description: 'Please choose Clean to set up a fresh database, or select Restore to recover a database from a backup.\n\n---\n\n'),

        validatingString(
            name: 'SQL_INSTANCE_VOLUME_SIZE',
            defaultValue: '100',
            regex: /^([1-9][0-9][0-9]|1000)$/,
            failedValidationMessage: 'The volume size must be between 100-1000 GB.',
            description: 'Please provide the SQL volume size in GB. The value must be between 100-1000 GB.'),

        validatingString(
            name: 'JMETER_INSTANCE_VOLUME_SIZE',
            defaultValue: '100',
            regex: /^([1-9][0-9][0-9]|1000)$/,
            failedValidationMessage: 'The volume size must be between 100-1000 GB.',
            description: 'Please provide the JMeter volume size in GB. The value must be between 100-1000 GB.'),

        [$class: 'CascadeChoiceParameter',
            choiceType: 'PT_SINGLE_SELECT',
            description: 'Choose the database version to restore from the list in the DataBaseBackUps directory',
            filterLength: 1,
            filterable: true,
            name: 'RESTORE_DATABASE_VERSION',
            randomName: 'choice-parameter-74996024839170',
            referencedParameters: 'INFRASTRUCTURE_TYPE',
            script: [
                    $class: 'ScriptlerScript',
                    scriptlerScriptId: 'getAwsOrAzureRepoList.groovy',
                    parameters: [
                            [name:'cloudProvider', value:'$INFRASTRUCTURE_TYPE'],
                            [name:'azureStorageAccountName', value: PerformanceStaticDataAzureStorageAccount],
                            [name:'azureContainerName', value: PerformanceStaticDataAzureContainer],
                            [name:'awsBucketName', value: PerformanceStaticDataS3Bucket],
                            [name:'awsRepositoryName', value: PerformanceStaticDataS3Repo],
                            [name:'region', value: 'us-east-1'],
                            [name:'folderName', value: '']
                    ]
                ]
        ],

        [$class: 'CascadeChoiceParameter',
            choiceType: 'PT_SINGLE_SELECT',
            description: 'Select the description of database that needs to be restored',
            filterLength: 1,
            filterable: true,
            name: 'RESTORE_DATABASE_DESCRIPTION',
            randomName: 'choice-parameter-74246024839168',
            referencedParameters: 'RESTORE_DATABASE_VERSION, INFRASTRUCTURE_TYPE',
            script: [
                    $class: 'ScriptlerScript',
                    scriptlerScriptId: 'getAwsOrAzureRepoList.groovy',
                    parameters: [
                            [name:'cloudProvider', value:'$INFRASTRUCTURE_TYPE'],
                            [name:'azureStorageAccountName', value: PerformanceStaticDataAzureStorageAccount],
                            [name:'azureContainerName', value: PerformanceStaticDataAzureContainer],
                            [name:'awsBucketName', value: PerformanceStaticDataS3Bucket],
                            [name:'awsRepositoryName', value: PerformanceStaticDataS3Repo],
                            [name:'region', value: 'us-east-1'],
                            [name:'folderName', value: '$RESTORE_DATABASE_VERSION']
                    ]
                ]
        ],

        string(
            name: 'IMPERSONATOR_DEV_NAME_FILTER',
            defaultValue: 'Sim<>%',
            description: 'Please provide impersonator device name filter.'),

        choice(
            name: 'MC_FUNCTIONALITY_TYPE',
            choices: ['FileTransfer', 'Generic'],
            description: 'Functionality type Generic or involving file transfer\n\n---\n\n'),

        choice(
            name: 'MC_SEARCH_TYPE',
            choices: ['SotiSearch', 'SotiSearch-SeparateBox', 'ElasticSearch'],
            description: 'The type of search to be used for MobiControl.\n\n---\n\n'),

        choice(
            name: 'MOBICONTROL_SS_INSTANCE_TYPE',
            choices: ['2xlarge-2xRAM', '2xlarge', '4xlarge-2xRAM', '4xlarge', 'xlarge-2xRAM', 'xlarge', 'large-2xRAM', 'large', 'nightlybuildxlarge'],
            description: 'The instance type to use for the Soti Search Server instance (\n *Note: Only applicable for SotiSearch-SeparateBox).\n\n'
                + 'Type | &nbsp;EC2-Equivalent | &nbsp;Azure-Equivalent | &nbsp;RAM(GB) | &nbsp;vCPU\n'
                + ':--- | :--- | ---: | ---: | ---:\n'
                + 'large | &nbsp;m5.large | &nbsp;Standard_D2s_v6 | 8 | 2\n'
                + 'xlarge | &nbsp;m5.xlarge | &nbsp;Standard_D4s_v6 | 16 | 4\n'
                + '2xlarge | &nbsp;m5.2xlarge | &nbsp;Standard_D8s_v6 | 32 | 8\n'
                + '4xlarge | &nbsp;m5.4xlarge | &nbsp;Standard_D16s_v6 | 64 | 16\n'
                + 'large-2xRAM | &nbsp;z1d.large | &nbsp;Standard_E2as_v6 | 16 | 2\n'
                + 'xlarge-2xRAM | &nbsp;z1d.xlarge | &nbsp;Standard_E4as_v6 | 32 | 4\n'
                + '2xlarge-2xRAM | &nbsp;z1d.2xlarge | &nbsp;Standard_E8as_v6 | 64 | 8\n'
                + '\n---\n\n'),

        string(
            name: 'DEVICE_FAMILIES',
            defaultValue: 'AndroidPlus',
            description: 'The comma-separated list of device families.\nValid values: \'AndroidPlus\', \'WindowsCE\', \'iOS\', \'AndroidEnterprise\', \'WindowsModern\'.\n\n---\n\n'),

        string(
            name: 'DS_MACHINE_COUNT',
            defaultValue: '1',
            description: 'Please provide the machine count for DS to be assigned to the environment.\n\n---\n\n'),

        string(
            name: 'DEVICE_SIMULATOR_MACHINE_COUNT',
            defaultValue: '3',
            description: 'Please provide the machine count for Device Simulators  to be assigned to the environment.\n\n---\n\n'),

        string(
            name: 'XTHUB_MACHINE_COUNT',
            defaultValue: '0',
            description: '**Please modify above value only if XTHUB instances are required in the environment.**\n\n---\n\n'),

        string(
            name: 'DEVICE_COUNT_PER_SIMULATOR_VM',
            defaultValue: '100',
            description: 'The number of simulated devices enrolled from each Device Simulator instance.\n\n---\n\n'),

        string(
            name: 'MOBICONTROL_INSTALLER_URL',
            defaultValue: 'https://artifactory.soti.net/artifactory/MobiControl/v2025.1.0/41105/MobiControl202510Setup_41105_release.exe',
            description: 'The URL of the MobiControl installer to install.\nSupported versions: 14.4.x or higher.\nThis URL must be accessible from the company\'s Data Centre.\n\n---\n\n'),

        [$class: 'ChoiceParameter',
         choiceType: 'PT_SINGLE_SELECT',
         description: 'Select the branch for JMeter Scripts',
         filterLength: 1,
         filterable: true,
         name: 'JMETER_SCRIPTS_BRANCH',
         randomName: 'choice-parameter-789620673153628',
         script: [
            $class: 'ScriptlerScript',
            scriptlerScriptId: 'getGitHubRepositoryBranches.groovy',
            parameters: [
                    [name:'RepositoryOwnerAndName', value:'MobiControl/MobiControlPerformanceTestingScripts'],
                    [name:'BranchPrefixFilters', value: 'master,release/'],
                    [name:'DefaultBranch', value: 'master']
                ]
            ]
        ],

        string(
            name: 'CURRENT_OWNER_TAG',
            defaultValue: 'Unassigned',
            description: 'Please provide the value of Current Owner Tag to be assigned to the environment.\n\n---\n\n'),

        string(
            name: 'REGISTRATION_CODE',
            defaultValue: '',
            description: 'If empty, offline activation is performed.\nTo use online activation, create a new license or reset an existing one using Customer Manager and enter the key here.\n\n---\n\n'),

        [$class: 'ChoiceParameter',
        choiceType: 'PT_SINGLE_SELECT',
        description: 'Select the suite name to be used for data insertion',
        filterLength: 1,
        filterable: true,
        name: 'DATA_INSERTION_SUITE_NAME',
        randomName: 'choice-parameter-3897548347547481',
        script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId:'getDataInsertionSuiteNames.groovy'
            ]
        ],
        [$class: 'CascadeChoiceParameter',
        choiceType: 'PT_CHECKBOX',
        description: 'Select the scenarios from the list for data insertion',
        filterLength: 1,
        filterable: true,
        name: 'DATA_INSERTION_SCENARIO',
        randomName: 'choice-parameter-3897549400235774',
        referencedParameters: 'DATA_INSERTION_SUITE_NAME',
        script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId:'getDataInsertionScenarioNames.groovy',
                parameters: [
                        [name:'DataInsertionSuiteName', value: '$DATA_INSERTION_SUITE_NAME']
                ]
            ]
        ],
        [$class: 'ChoiceParameter',
        choiceType: 'PT_SINGLE_SELECT',
        description: 'Select the platform to be used for test execution',
        filterLength: 1,
        filterable: true,
        name: 'TEST_EXECUTION_PLATFORM_NAME',
        randomName: 'choice-parameter-3897548347547481',
        script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId:'getTestExecutionPlatformNames.groovy'
            ]
        ],
        [$class: 'CascadeChoiceParameter',
        choiceType: 'PT_MULTI_SELECT',
        description: 'Select the suite names from the list for test execution',
        filterLength: 1,
        filterable: true,
        name: 'TEST_EXECUTION_SUITE_NAME',
        randomName: 'choice-parameter-3897549400235775',
        referencedParameters: 'TEST_EXECUTION_PLATFORM_NAME',
        script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId:'getTestExecutionSuiteNames.groovy',
                parameters: [
                        [name:'TestExecutionPlatformName', value: '$TEST_EXECUTION_PLATFORM_NAME']
                    ]
            ]
        ],
        [$class: 'CascadeChoiceParameter',
         choiceType: 'PT_MULTI_SELECT',
         description: 'Select the scenarios from the list for test executiom',
         filterLength: 1,
         filterable: true,
         name: 'TEST_EXECUTION_SCENARIO_NAME',
         randomName: 'choice-parameter-3897549400235776',
         referencedParameters: 'TEST_EXECUTION_PLATFORM_NAME, TEST_EXECUTION_SUITE_NAME',
         script: [
            $class: 'ScriptlerScript',
            scriptlerScriptId:'getTestExecutionScenarioNames.groovy',
            parameters: [
                    [name:'TestExecutionPlatformName', value: '$TEST_EXECUTION_PLATFORM_NAME'],
                    [name:'TestExecutionSuiteName', value: '$TEST_EXECUTION_SUITE_NAME']
                ]
            ]
        ],
        [$class: 'CascadeChoiceParameter',
         choiceType: 'PT_MULTI_SELECT',
         description: 'Select the scenario scripts from the list for test execution',
         filterLength: 1,
         filterable: true,
         name: 'TEST_EXECUTION_SCENARIO_SCRIPT_NAME',
         randomName: 'choice-parameter-3897549400235777',
         referencedParameters: 'TEST_EXECUTION_PLATFORM_NAME, TEST_EXECUTION_SUITE_NAME, TEST_EXECUTION_SCENARIO_NAME',
         script: [
            $class: 'ScriptlerScript',
            scriptlerScriptId:'getTestExecutionScenarioScriptName.groovy',
            parameters: [
                    [name:'TestExecutionPlatformName', value: '$TEST_EXECUTION_PLATFORM_NAME'],
                    [name:'TestExecutionSuiteName', value: '$TEST_EXECUTION_SUITE_NAME'],
                    [name:'TestExecutionScenarioName', value: '$TEST_EXECUTION_SCENARIO_NAME']
                ]
            ]
        ],

        // Rarely changed parameters
        choice(
            name: 'SQL_VERSION',
            choices: ['SQL2022', 'SQL2019', 'SQL2016'],
            description: 'Select SQL version.\n\n---\n\n'),

        [$class: 'CascadeChoiceParameter',
            choiceType: 'PT_SINGLE_SELECT',
            description: 'The instance type to use for the APNS Simulator instance.\n\n'
                + 'Type | &nbsp;EC2-Equivalent | &nbsp;Azure-Equivalent | &nbsp;RAM(GB) | &nbsp;vCPU\n'
                + ':--- | :--- | :--- | ---: | ---:\n'
                + 'medium | &nbsp;t3.medium | &nbsp;Standard_F2als_v6 | 4 | 2\n'
                + 'large | &nbsp;t3.large | &nbsp;Standard_D2s_v6 | 8 | 2\n'
                + 'xlarge | &nbsp;t3.xlarge | &nbsp;Standard_D4s_v6 | 16 | 4\n'
                + '2xlarge | &nbsp;t3.2xlarge | &nbsp;Standard_D8s_v6 | 32 | 8\n'
                + '\n---\n\n',
            filterLength: 1,
            filterable: true,
            name: 'APNS_SIMULATOR_INSTANCE_TYPE',
            randomName: 'choice-parameter-3197548347547411',
            referencedParameters: 'ENVIRONMENT_DEVICE_SCALE',
            script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId: 'getInstanceTypeChoices.groovy',
                parameters: [
                    [name: 'InstanceTypeCategory', value: 'APNS'],
                    [name: 'EnvironmentDeviceScale', value: '$ENVIRONMENT_DEVICE_SCALE']
                ]
            ]
        ],

        [$class: 'CascadeChoiceParameter',
            choiceType: 'PT_SINGLE_SELECT',
            description: 'The instance type to use for the Device Simulator instances.\n\n'
                + 'Type | &nbsp;EC2-Equivalent | &nbsp;Azure-Equivalent | &nbsp;RAM(GB) | &nbsp;vCPU\n'
                + ':--- | :--- | ---: | ---: | ---:\n'
                + 'xlarge | &nbsp;m5.xlarge | &nbsp;Standard_D4s_v6 | 16 | 4\n'
                + 'xlarge_customized | &nbsp;m5.xlarge | &nbsp;Standard_D4s_v6 | 8 | 4\n'
                + '2xlarge | &nbsp;m5.2xlarge | &nbsp;Standard_D8s_v6 | 32 | 8\n'
                + '\n---\n\n',
            filterLength: 1,
            filterable: true,
            name: 'DEVICE_SIMULATOR_INSTANCE_TYPE',
            randomName: 'choice-parameter-3297548347547411',
            referencedParameters: 'ENVIRONMENT_DEVICE_SCALE',
            script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId: 'getInstanceTypeChoices.groovy',
                parameters: [
                    [name: 'InstanceTypeCategory', value: 'SIMULATOR'],
                    [name: 'EnvironmentDeviceScale', value: '$ENVIRONMENT_DEVICE_SCALE']
                ]
            ]
        ],

        [$class: 'CascadeChoiceParameter',
            choiceType: 'PT_SINGLE_SELECT',
            description: 'The instance type to use for the JMeter instance.\n\n'
                + 'Type | &nbsp;EC2-Equivalent | &nbsp;Azure-Equivalent | &nbsp;RAM(GB) | &nbsp;vCPU\n'
                + ':--- | :--- | ---: | ---: | ---:\n'
                + 'medium | &nbsp;t3.medium | &nbsp;Standard_F2als_v6 | 4 | 2\n'
                + 'large | &nbsp;m5.large | &nbsp;Standard_D2s_v6 | 8 | 2\n'
                + 'xlarge | &nbsp;m5.xlarge | &nbsp;Standard_D4s_v6 | 16 | 4\n'
                + '2xlarge | &nbsp;m5.2xlarge | &nbsp;Standard_D8s_v6 | 32 | 8\n'
                + '4xlarge | &nbsp;m5.4xlarge | &nbsp;Standard_D16s_v6 | 64 | 16\n'
                + '\n---\n\n',
            filterLength: 1,
            filterable: true,
            name: 'JMETER_INSTANCE_TYPE',
            randomName: 'choice-parameter-3397548347547411',
            referencedParameters: 'ENVIRONMENT_DEVICE_SCALE',
            script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId: 'getInstanceTypeChoices.groovy',
                parameters: [
                    [name: 'InstanceTypeCategory', value: 'JMETER'],
                    [name: 'EnvironmentDeviceScale', value: '$ENVIRONMENT_DEVICE_SCALE']
                ]
            ]
        ],

        [$class: 'CascadeChoiceParameter',
            choiceType: 'PT_SINGLE_SELECT',
            description: 'The instance type to use for the MobiControl Deployment Server (DS) instance(s).\n\n'
                + 'Type | &nbsp;EC2-Equivalent | &nbsp;Azure-Equivalent | &nbsp;RAM(GB) | &nbsp;vCPU\n'
                + ':--- | :--- | ---: | ---: | ---:\n'
                + 'large | &nbsp;m5.large | &nbsp;Standard_D2s_v6 | 8 | 2\n'
                + 'xlarge | &nbsp;m5.xlarge | &nbsp;Standard_D4s_v6 | 16 | 4\n'
                + '2xlarge | &nbsp;m5.2xlarge | &nbsp;Standard_D8s_v6 | 32 | 8\n'
                + '4xlarge | &nbsp;m5.4xlarge | &nbsp;Standard_D16s_v6 | 64 | 16\n'
                + 'large-2xRAM | &nbsp;z1d.large | &nbsp;Standard_E2as_v6 | 16 | 2\n'
                + 'xlarge-2xRAM | &nbsp;z1d.xlarge | &nbsp;Standard_E4as_v6 | 32 | 4\n'
                + '2xlarge-2xRAM | &nbsp;z1d.2xlarge | &nbsp;Standard_E8as_v6 | 64 | 8\n'
                + '\n---\n\n',
            filterLength: 1,
            filterable: true,
            name: 'MOBICONTROL_DS_INSTANCE_TYPE',
            randomName: 'choice-parameter-3497548347547411',
            referencedParameters: 'ENVIRONMENT_DEVICE_SCALE',
            script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId: 'getInstanceTypeChoices.groovy',
                parameters: [
                    [name: 'InstanceTypeCategory', value: 'DS'],
                    [name: 'EnvironmentDeviceScale', value: '$ENVIRONMENT_DEVICE_SCALE']
                ]
            ]
        ],

        [$class: 'CascadeChoiceParameter',
            choiceType: 'PT_SINGLE_SELECT',
            description: 'The instance type to use for the MobiControl Management Service (MS) instance(s).\n\n'
                + 'Type | &nbsp;EC2-Equivalent | &nbsp;Azure-Equivalent | &nbsp;RAM(GB) | &nbsp;vCPU\n'
                + ':--- | :--- | ---: | ---: | ---:\n'
                + 'large | &nbsp;m5.large | &nbsp;Standard_D2s_v6 | 8 | 2\n'
                + 'xlarge | &nbsp;m5.xlarge | &nbsp;Standard_D4s_v6 | 16 | 4\n'
                + '2xlarge | &nbsp;m5.2xlarge | &nbsp;Standard_D8s_v6 | 32 | 8\n'
                + '4xlarge | &nbsp;m5.4xlarge | &nbsp;Standard_D16s_v6 | 64 | 16\n'
                + 'large-2xRAM | &nbsp;z1d.large | &nbsp;Standard_E2as_v6 | 16 | 2\n'
                + 'xlarge-2xRAM | &nbsp;z1d.xlarge | &nbsp;Standard_E4as_v6 | 32 | 4\n'
                + '2xlarge-2xRAM | &nbsp;z1d.2xlarge | &nbsp;Standard_E8as_v6 | 64 | 8\n'
                + '3xlarge-2xRAM | &nbsp;z1d.3xlarge | &nbsp;Standard_E16as_v6 | 96 | 12\n'
                + '\n---\n\n',
            filterLength: 1,
            filterable: true,
            name: 'MOBICONTROL_MS_INSTANCE_TYPE',
            randomName: 'choice-parameter-3597548347547411',
            referencedParameters: 'ENVIRONMENT_DEVICE_SCALE',
            script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId: 'getInstanceTypeChoices.groovy',
                parameters: [
                    [name: 'InstanceTypeCategory', value: 'MS'],
                    [name: 'EnvironmentDeviceScale', value: '$ENVIRONMENT_DEVICE_SCALE']
                ]
            ]
        ],

        [$class: 'CascadeChoiceParameter',
            choiceType: 'PT_SINGLE_SELECT',
            description: 'The instance type to use for the SQL instance(s).\n\n'
                + 'Type | &nbsp;EC2-Equivalent | &nbsp;Azure-Equivalent | &nbsp;RAM(GB) | &nbsp;vCPU\n'
                + ':--- | :--- | ---: | ---: | ---:\n'
                + 'large | &nbsp;m5.large | &nbsp;Standard_D2s_v6 | 8 | 2\n'
                + 'xlarge | &nbsp;m5.xlarge | &nbsp;Standard_D4s_v6 | 16 | 4\n'
                + '2xlarge | &nbsp;m5.2xlarge | &nbsp;Standard_D8s_v6 | 32 | 8\n'
                + '4xlarge | &nbsp;m5.4xlarge | &nbsp;Standard_D16s_v6 | 64 | 16\n'
                + 'SQL-large | &nbsp;i3en.large | &nbsp;Standard_E2ds_v6 | 16 | 2\n'
                + 'SQL-xlarge | &nbsp;i3en.xlarge | &nbsp;Standard_E4as_v6 | 32 | 4\n'
                + 'SQL-2xlarge | &nbsp;i3en.2xlarge | &nbsp;Standard_E8ds_v6 | 64 | 8\n'
                + 'SQL-3xlarge | &nbsp;z1d.3xlarge | &nbsp;Standard_E16as_v6 | 96 | 12\n'
                + 'SQL-4xlarge | &nbsp;i3en.6xlarge | &nbsp;Standard_E16as_v6 | 128 | 16\n'
                + 'SQL-6xlarge | &nbsp;z1d.6xlarge | &nbsp;Standard_E20as_v6 | 192 | 24\n'
                + '\n---\n\n',
            filterLength: 1,
            filterable: true,
            name: 'SQL_SERVER_INSTANCE_TYPE',
            randomName: 'choice-parameter-3697548347547411',
            referencedParameters: 'ENVIRONMENT_DEVICE_SCALE',
            script: [
                $class: 'ScriptlerScript',
                scriptlerScriptId: 'getInstanceTypeChoices.groovy',
                parameters: [
                    [name: 'InstanceTypeCategory', value: 'SQL'],
                    [name: 'EnvironmentDeviceScale', value: '$ENVIRONMENT_DEVICE_SCALE']
                ]
            ]
        ],

        choice(
            name: 'XTHUB_INSTANCE_TYPE',
            choices: ['large', 'medium', 'xlarge', '2xlarge', '4xlarge', 'nightlybuildxlarge'],
            description: 'The instance type to use for the XTHub instance.\n\n'
                + 'Type | &nbsp;EC2-Equivalent | &nbsp;Azure-Equivalent | &nbsp;RAM(GB) | &nbsp;vCPU\n'
                + ':--- | :--- | ---: | ---: | ---:\n'
                + 'medium | &nbsp;t3.medium | &nbsp;Standard_F2als_v6 | 4 | 2\n'
                + 'large | &nbsp;m5.large | &nbsp;Standard_D2s_v6 | 8 | 2\n'
                + 'xlarge | &nbsp;m5.xlarge | &nbsp;Standard_D4s_v6 | 16 | 4\n'
                + '2xlarge | &nbsp;m5.2xlarge | &nbsp;Standard_D8s_v6 | 32 | 8\n'
                + '4xlarge | &nbsp;m5.4xlarge | &nbsp;Standard_D16s_v6 | 64 | 16\n'
                + '\n---\n\n'),

        choice(
            name: 'IOS_CONSOLE_RUNNER_VERSION',
            choices: ['4.1.0','1.20.0','1.17.3','1.17.1'],
            description: 'Select the version of Soti.Simulation.IosConsoleRunner.\n\n'
                + 'Version | Description\n'
                + ':--- | :---\n'
                + '1.17.1 | supports DDM iOS native profiles installation\n'
                + '1.17.3 | supports creating devices with a Unique MAC address, Serial Number\n'
                + '1.20.0 | Default version -supports reusing clientid when creating more devices, checkin issues after env restoration are resolved\n'
                + '4.1.0  | Migration to .NET 8, DDM firmwarePolicyStatusUpdates, Fixed certificate issues\n'
                + '\n---\n\n'),

        booleanParam(
            defaultValue: false,
            description: 'Select to enable DDM in Apple iOS Enrollment Policy',
            name: 'ENABLE_DDM'),

        string(
            name: 'NEW_SIMULATOR_URL',
            defaultValue: 'https://artifactory-perf.soti.net/artifactory/MobiControl_PerformanceTesting/NewSimulator/v2026.0.0/Simulator_v2026.0.0_MC301590_MC221988_MC302860_25Apr2025.zip',
            description: 'The URL of the ZIP file containing the Android+ and WindowsMobile simulator binaries.\nThis URL must be accessible from the company\'s Data Centre.\n\nAlternatively, apply this URL https://artifactory-perf.soti.net/artifactory/Simulators-Temp/NewSimulatorRecourses/New_SimulatorHost_V4.21.20.zip for using the new Android Simulator developed by SOTI-one-simulators team.\n\n---\n\n'),

        string(
            name: 'TELEGRAF_SERVICE_URL',
            defaultValue: 'https://artifactory-perf.soti.net/artifactory/MobiControl_PerformanceTesting/TelegrafService/TelegrafService_2024-02-28.zip',
            description: 'The URL of the ZIP file containing the Telegraf service binaries.\nThis URL must be accessible from the company\'s Data Centre.\n\n---\n\n'),
        string(
            name: 'MOCK_SOTISERVICE_FILE_URL',
            defaultValue: 'https://artifactory-perf.soti.net/artifactory/MobiControl_PerformanceTesting/NewSimulator/MockSotiService.zip',
            description: 'The URL of the ZIP file containing the Mock SotiService binaries.\nThis URL must be accessible from the company\'s Data Centre.\n\n---\n\n'),
        booleanParam(
            defaultValue: false,
            description: 'Select to enable Snapshot/Volume creation/restoration (not required in normal flow execution).',
            name: 'ENABLE_SNAPSHOT_VOLUME_CREATION_RESTORATION'),
        string(
            name: 'WINDOWS_MODERN_PACKAGE_URL',
            defaultValue: 'https://artifactory-perf.soti.net/artifactory/MobiControl_PerformanceTesting/NewSimulator/v2025.1.0/WM-SimulatorHost_V1.9.1.0_DevOps.zip',
            description: 'The URL of the ZIP file containing the Windows Modern package binaries.\nThis URL must be accessible from the company\'s Data Centre.\n\n---\n\n'),
        string(
            name: 'UPSTREAM_SCENARIOS_TYPE',
            description: 'Needs to be passed from upstream job only. Please dont touch this parameter.\n\n---\n\n'),
        string(
            name: 'UPSTREAM_TRIGGERED_BY',
            defaultValue: 'TIMER',
            description: 'Needs to be passed from upstream job only. Please dont touch this parameter.\n\n---\n\n'),
        booleanParam(
            defaultValue: false,
            description: 'Needs to be passed from upstream job only. Please dont touch this parameter \n (*Note: If checked nightly triggered stacks will be required to be deleted manually) \n\n---\n\n',
            name: ' UPSTREAM_DELETE_STACK_MANUALLY')
    ]
}

void terminateCloudResources()
{
    String stackName = readJSON(text: readFile("${WORKSPACE}/${ArtifactsIn}/${EnvironmentConfigurationFileName}").trim().replaceAll('^\uFEFF', '')).StackName

    println("Terminating cloud Resources using 'Stack Name: ${stackName}' as the filter")

    if(stackName != null && stackName.trim().length() > 0)
    {
        String operationType = 'terminate'
        String infrastructureType = params.INFRASTRUCTURE_TYPE

        println("terminateCloudResources: infrastructureType:${infrastructureType} operationType:${operationType} stackName:${stackName}")

        build(
            wait: true, 
            propagate: true, 
            job: 'ManageStack',
            parameters: [
                string(name: 'INFRASTRUCTURE_TYPE', value: infrastructureType),
                string(name: 'OPERATION_TYPE', value: operationType),
                string(name: 'STACK_LIST', value: stackName)])
    }
}

void triggerUpstreamJobStageDurationStatistics()
{
    build(
        job: 'Get-UpstreamJob-StageDurationStatistics',
        wait: false,
        propagate: false,
        parameters: [
            string(name: 'PREFIX', value: env.JOB_NAME)]
    )
}

properties([
    parameters(getParameterList())
])

pipeline
{
    agent none

    options
    {
        timestamps()
        preserveStashes(buildCount: 50)
    }

    stages
    {
        stage('PrepareEnvSetup')
        {
            agent
            {
                label AgentLabel
            }
            options
            {
                timeout(time: 60, unit: 'MINUTES')
            }
            environment
            {
                BUILDCONFIG_FILE_PATH = "${WORKSPACE}\\${ArtifactsIn}\\.ci\\PackagingStage\\Packaging.json"
            }
            steps
            {
                prepareEnvSetup()
            }
            post
            {
                always
                {
                    archiveArtifacts artifacts: "${STAGE_NAME}\\**\\*"
                    publishReports(env.STAGE_NAME, 'BuildEvents.Report.html', 'Build Report')
                    setBuildDescription()
                }
                aborted
                {
                    script
                    {
                        sendNotification("Build aborted, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Aborted at ${STAGE_NAME}")
                    }
                }
                failure
                {
                    script
                    {
                        sendNotification("Build failed, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Failed at ${STAGE_NAME}")
                    }
                }
            }
        }
        stage('SetupStack')
        {
            when
            {
                expression { !skipStageExecution()}
                beforeAgent true
            }
            agent
            {
                label AgentLabel
            }
            options
            {
                timeout(time: 10, unit: 'HOURS')
            }
            environment
            {
                BUILDCONFIG_FILE_PATH = "${WORKSPACE}\\${ArtifactsIn}\\.ci\\SetupStage\\Setup.json"
                CF_TIMEOUT_IN_MINUTES = '180'
                LOCAL_STACK_CREATION_TIMEOUT = '00:30:00'
            }
            steps
            {
                catchError(stageResult: 'FAILURE')
                {
                    cleanWs()
                    copySourceCode('ciFolder.zip')
                    echo "Installing dependency scripts."
                    internalInstallPowerShellGetScripts(CommonPsGetScriptsDefinition)

                    setupStack()
                }
            }
            post
            {
                always
                {
                    zip zipFile: 'destroyStack.zip',
                        archive: true,
                        dir: "${ArtifactsIn}/.ci",
                        exclude: '**/**.exe'
                    archiveArtifacts artifacts: "${STAGE_NAME}\\**\\*"
                    publishReports(env.STAGE_NAME, "BuildEvents.Report.html, ${StackInfoFileNameOnly}.html", 'Build Report, Result')
                }
                success 
                {   
                    script 
                    {
                       alertUserForPipelineInput()
                    }
                }
                aborted
                {
                    script
                    {
                        sendNotification("Build aborted, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Aborted at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                    }
                }
                failure
                {
                    script
                    {
                        sendNotification("Build failed, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Failed at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                        LAST_FAILURE_STAGE = env.STAGE_NAME
                    }
                }
            }
        }
        stage('ConfirmPrepareDeviceEnrollment')
        {
            when
            {
                expression { !GO_TO_DELETE_STAGE && !skipStageExecution()}
            }
            agent none
            steps
            {
                script
                {
                    if(!isTriggeredByUpstreamJob(UpstreamNightlyTriggerJob))
                    {
                        input message: 'Pipeline PAUSED, should we continue?'
                    }
                }
            }
        }
        stage('PrepareDeviceEnrollment')
        {
            when
            {
                expression { !GO_TO_DELETE_STAGE && !skipStageExecution()}
            }
            agent
            {
                label AgentLabel
            }
            environment
            {
                BUILDCONFIG_FILE_PATH = "${WORKSPACE}\\${ArtifactsIn}\\.ci\\PreEnrollmentStage\\PreEnrollment.json"
            }
            steps
            {
                catchError(stageResult: 'FAILURE')
                {
                    prepareDeviceEnrollment()
                }
            }
            post
            {
                always
                {
                    archiveArtifacts artifacts: "${STAGE_NAME}\\**\\*"
                    publishReports(env.STAGE_NAME, 'BuildEvents.Report.html', 'Build Report')
                }
                aborted
                {
                    script
                    {
                        sendNotification("Build aborted, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Aborted at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                    }
                }
                failure
                {
                    script
                    {
                        sendNotification("Build failed, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Failed at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                        LAST_FAILURE_STAGE = env.STAGE_NAME
                    }
                }
            }
        }
        stage('EnrollSimulatedDevices')
        {
            when
            {
                expression { !GO_TO_DELETE_STAGE && !skipStageExecution()}
                beforeAgent true
            }
            agent
            {
                label AgentLabel
            }
            environment
            {
                BUILDCONFIG_FILE_PATH = "${WORKSPACE}\\${ArtifactsIn}\\.ci\\EnrollmentStage\\Enrollment.json"
            }
            steps
            {
                catchError(stageResult: 'FAILURE')
                {
                    cleanWs()
                    echo "Installing dependency scripts."
                    internalInstallPowerShellGetScripts(CommonPsGetScriptsDefinition)

                    script
                    {
                        fetchArtifacts('SetupStack', "${StackInfoFileNameOnly}${StackInfoFileExtension}", "${WORKSPACE}/${ArtifactsIn}")
                        withVault([vaultSecrets: getVaultSecrets()])
                        {
                            def enrollSimulatedDevicesInjectedVariables =
                                """@{
                                        InfrastructureType = '${params.INFRASTRUCTURE_TYPE}'
                                        DevOpsDataRootDir = '${DevOpsDataRootDir}'
                                        EnrollmentDeviceFamilies = '${params.DEVICE_FAMILIES}'
                                        DeviceCountPerSimulatorVM = '${params.DEVICE_COUNT_PER_SIMULATOR_VM}'
                                        StackInfoFilePath = '\$In:${StackInfoFileNameOnly}${StackInfoFileExtension}'
                                        Region = '${getRegion()}'
                                        AccessKey = '${AWS_ACCESS_KEY}'
                                        SecretKey = '${AWS_SECRET_KEY}'
                                        EnrollmentTolerancePercentage = '${EnrollmentTolerancePercentage}'
                                        DataBaseSetupType = '${params.DATABASE_SETUP}'
                                        DeviceNameFilter = '${params.IMPERSONATOR_DEV_NAME_FILTER}'
                                        StaticInputDataContainerName = '${StaticInputDataContainerName}'
                                        StaticDataBucket = '${PerformanceStaticDataS3Bucket}'
                                        StorageAccountName = '${PerformanceStaticDataAzureStorageAccount}'
                                        ContainerName = '${PerformanceStaticDataAzureContainer}'
                                        SearchServiceName = '${buildVariables.SEARCH_SERVICE_NAME}'
                                    }
                                """
                            executeIndividualTasks(BUILDCONFIG_FILE_PATH, enrollSimulatedDevicesInjectedVariables)
                        }
                    }
                }
            }
            post
            {
                always
                {
                    archiveArtifacts artifacts: "${STAGE_NAME}\\**\\*"
                    publishReports(env.STAGE_NAME, 'BuildEvents.Report.html', 'Build Report')
                }

                aborted
                {
                    script
                    {
                        sendNotification("Build aborted, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Aborted at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                    }
                }

                failure
                {
                    script
                    {
                        sendNotification("Build failed, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Failed at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                        LAST_FAILURE_STAGE = env.STAGE_NAME
                    }
                }
            }
        }
        stage('DataInsertion')
        {
            when
            {
                expression { !GO_TO_DELETE_STAGE && !skipStageExecution()}
                beforeAgent true
            }
            agent
            {
                label AgentLabel
            }
            environment
            {
                BUILDCONFIG_FILE_PATH = "${WORKSPACE}\\${ArtifactsIn}\\.ci\\DataInsertionStage\\DataInsertion.json"
            }
            steps
            {
                catchError(stageResult: 'FAILURE')
                {
                    cleanWs()
                    copySourceCode('ciFolder.zip')
                    echo "Installing dependency scripts."
                    internalInstallPowerShellGetScripts(CommonPsGetScriptsDefinition)

                    script
                    {
                        fetchArtifacts('SetupStack', "${StackInfoFileNameOnly}${StackInfoFileExtension}", "${WORKSPACE}/${ArtifactsIn}")
                        fetchArtifacts('PrepareEnvSetup', EnvironmentConfigurationFileName, "${WORKSPACE}/${ArtifactsIn}")
                        fetchArtifacts(env.STAGE_NAME, "${SnapshotMappingFileNameOnly}.${env.STAGE_NAME}${SnapshotMappingFileExtension}", "${WORKSPACE}/${ArtifactsIn}", true)
                        withVault([vaultSecrets: getVaultSecrets()])
                        {
                            String dataInsertionScenarioNames = ''
                            boolean isThisStageRestarted = isStageRestarted(env.STAGE_NAME)

                            isRestartAllowed(isThisStageRestarted)
                            List<String> includeTags = determineTags(isThisStageRestarted, params.INFRASTRUCTURE_TYPE)

                            if (isThisStageRestarted)
                            {
                                def dataInsertionScenario = input(
                                    message: 'Select the suite and scenarios to be used for data insertion',
                                    parameters:
                                    [
                                        [
                                            $class: 'ChoiceParameter',
                                            choiceType: 'PT_SINGLE_SELECT',
                                            description: 'Select the suite name to be used for data insertion',
                                            filterLength: 1,
                                            filterable: true,
                                            name: 'RERUN_DATA_INSERTION_SUITE_NAME',
                                            randomName: 'choice-parameter-3897548347547481',
                                            script:
                                            [
                                                $class: 'ScriptlerScript',
                                                scriptlerScriptId:'getDataInsertionSuiteNames.groovy'
                                            ]
                                        ],
                                        [
                                            $class: 'CascadeChoiceParameter',
                                            choiceType: 'PT_CHECKBOX',
                                            description: 'Select the scenarios from the list for data insertion',
                                            filterLength: 1,
                                            filterable: true,
                                            name: 'RERUN_DATA_INSERTION_SCENARIO',
                                            randomName: 'choice-parameter-3897549400235774',
                                            referencedParameters: 'RERUN_DATA_INSERTION_SUITE_NAME',
                                            script:
                                            [
                                                $class: 'ScriptlerScript',
                                                scriptlerScriptId:'getDataInsertionScenarioNames.groovy',
                                                parameters:
                                                [
                                                    [name:'DataInsertionSuiteName', value: '$RERUN_DATA_INSERTION_SUITE_NAME']
                                                ]
                                            ]
                                        ]
                                    ])

                                dataInsertionScenarioNames = "${dataInsertionScenario.RERUN_DATA_INSERTION_SCENARIO}"
                            }
                            else
                            {
                                dataInsertionScenarioNames = params.DATA_INSERTION_SCENARIO
                            }

                            println "dataInsertionScenarioNames = <${dataInsertionScenarioNames}>"
                            println "dataInsertionSuiteName = <${params.DATA_INSERTION_SUITE_NAME}>"
                            def dataInsertionInjectedVariables =
                                """@{
                                        InfrastructureType = '${params.INFRASTRUCTURE_TYPE}'
                                        DevOpsDataRootDir = '${DevOpsDataRootDir}'
                                        VmPoolBaseUrl = '${VmPoolBaseUrl}'
                                        VmPoolAuthToken = '${VMPOOL_AUTH_TOKEN}'
                                        Region = '${getRegion()}'
                                        AccessKey = '${AWS_ACCESS_KEY}'
                                        SecretKey = '${AWS_SECRET_KEY}'
                                        StageName = '${STAGE_NAME}'
                                        DataInsertionResultsBaseDirectory = "${DevOpsDataRootDir}/DataInsertionResults"
                                        JMeterScriptsDirectory = "${DevOpsDataRootDir}/JMeterScripts"
                                        StackInfoFilePath = '\$In:${StackInfoFileNameOnly}${StackInfoFileExtension}'
                                        ConfigurationFilePath = '\$In:${EnvironmentConfigurationFileName}'
                                        DataInsertionScenarioNames = '${dataInsertionScenarioNames}'
                                        DestinationResultsDirectory = "${WORKSPACE}/${STAGE_NAME}"
                                        EnrollmentDeviceFamilies = '${params.DEVICE_FAMILIES}'
                                        DeviceCountPerSimulatorVM = '${params.DEVICE_COUNT_PER_SIMULATOR_VM}'
                                        ReconnectionTolerancePercentage = '${ReconnectionTolerancePercentage}'
                                        SnapshotManagementTimeout = '${SnapshotManagementTimeout}'
                                        SnapshotMappingFilePath = '\$In:${SnapshotMappingFileNameOnly}.${env.STAGE_NAME}${SnapshotMappingFileExtension}'
                                        ClientId = '${ARM_CLIENT_ID}'
                                        ClientSecret = '${ARM_CLIENT_SECRET}'
                                        TenantId = '${ARM_TENANT_ID}'
                                        SubscriptionId = '${ARM_SUBSCRIPTION_ID}'
                                        AzureInstanceDataDiskSkuType = '${AzureDataDiskSkuType}'
                                        AzureOsDiskSkuType = '${AzureOsDiskSkuType}'
                                        SearchServiceName = '${buildVariables.SEARCH_SERVICE_NAME}'
                                        SearchServiceDeploymentType = '${buildVariables.SEARCH_SERVICE_DEPLOYMENT_TYPE}'
                                        SearchServiceInstanceCount = '${buildVariables.SEARCH_SERVICE_INSTANCE_COUNT}'
                                        CostUsageTag = '${buildVariables.COST_USAGE_TAG}'
                                        CurrentOwnerTag = '${params.CURRENT_OWNER_TAG}'
                                        TriggeredByTag = '${LdapDetails.userEmail}'
                                        ManagerEmailTag = '${LdapDetails.managerEmail}'
                                        DataBaseSetupType = '${params.DATABASE_SETUP}'
                                    }
                                    """
                            executeMultiTasks(BUILDCONFIG_FILE_PATH, dataInsertionInjectedVariables, includeTags)
                        }
                    }
                }
            }
            post
            {
                always
                {
                    archiveArtifacts artifacts: "${STAGE_NAME}\\**\\*"
                    publishReports(env.STAGE_NAME, 'BuildEvents.Report.html', 'Build Report')
                }
                aborted
                {
                    script
                    {
                        sendNotification("Build aborted, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Aborted at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                    }
                }
                failure
                {
                    script
                    {
                        sendNotification("Build failed, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Failed at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                        LAST_FAILURE_STAGE = env.STAGE_NAME
                    }
                }
            }
        }
        stage('TestExecution')
        {
            when
            {
                expression { !GO_TO_DELETE_STAGE && !skipStageExecution()}
                beforeAgent true
            }
            agent
            {
                label AgentLabel
            }
            environment
            {
                BUILDCONFIG_FILE_PATH = "${WORKSPACE}\\${ArtifactsIn}\\.ci\\TestExecutionStage\\TestExecution.json"
            }
            steps
            {
                catchError(stageResult: 'FAILURE')
                {
                    cleanWs()
                    copySourceCode('ciFolder.zip')
                    echo "Installing dependency scripts."
                    internalInstallPowerShellGetScripts(CommonPsGetScriptsDefinition)
                    script
                    {
                        fetchArtifacts('SetupStack', "${StackInfoFileNameOnly}${StackInfoFileExtension}", "${WORKSPACE}/${ArtifactsIn}")
                        fetchArtifacts('PrepareEnvSetup', EnvironmentConfigurationFileName, "${WORKSPACE}/${ArtifactsIn}")
                        fetchArtifacts(env.STAGE_NAME, "${SnapshotMappingFileNameOnly}.${env.STAGE_NAME}${SnapshotMappingFileExtension}", "${WORKSPACE}/${ArtifactsIn}", true)
                        withVault([vaultSecrets: getVaultSecrets()])
                        {
                            def testExecutionParameters = []
                            String deviceFamilyFromPipeline = ''
                            boolean isThisStageRestarted = isStageRestarted(env.STAGE_NAME)

                            isRestartAllowed(isThisStageRestarted)
                            List<String> includeTags = determineTags(isThisStageRestarted, params.INFRASTRUCTURE_TYPE)

                            if (isStageRestarted('DataInsertion') || isThisStageRestarted)
                            {
                                def testExecutionScenario = input(
                                    message: 'Select the suite and scenarios to be used for data insertion',
                                    parameters:
                                    [
                                        [
                                            $class: 'ChoiceParameter',
                                            choiceType: 'PT_SINGLE_SELECT',
                                            description: 'Select the platform to be used for test execution',
                                            filterLength: 1,
                                            filterable: true,
                                            name: 'RERUN_TEST_EXECUTION_PLATFORM_NAME',
                                            randomName: 'choice-parameter-3897548347547481',
                                            script:
                                            [
                                                $class: 'ScriptlerScript',
                                                scriptlerScriptId:'getTestExecutionPlatformNames.groovy'
                                            ]
                                        ],
                                        [
                                            $class: 'CascadeChoiceParameter',
                                            choiceType: 'PT_MULTI_SELECT',
                                            description: 'Select the suite names from the list for test execution',
                                            filterLength: 1,
                                            filterable: true,
                                            name: 'RERUN_TEST_EXECUTION_SUITE_NAME',
                                            randomName: 'choice-parameter-3897549400235775',
                                            referencedParameters: 'RERUN_TEST_EXECUTION_PLATFORM_NAME',
                                            script:
                                            [
                                                $class: 'ScriptlerScript',
                                                scriptlerScriptId:'getTestExecutionSuiteNames.groovy',
                                                parameters:
                                                [
                                                    [name:'TestExecutionPlatformName', value: '$RERUN_TEST_EXECUTION_PLATFORM_NAME']
                                                ]
                                            ]
                                        ],
                                        [
                                            $class: 'CascadeChoiceParameter',
                                            choiceType: 'PT_MULTI_SELECT',
                                            description: 'Select the scenarios from the list for test executiom',
                                            filterLength: 1,
                                            filterable: true,
                                            name: 'RERUN_TEST_EXECUTION_SCENARIO_NAME',
                                            randomName: 'choice-parameter-3897549400235776',
                                            referencedParameters: 'RERUN_TEST_EXECUTION_PLATFORM_NAME, RERUN_TEST_EXECUTION_SUITE_NAME',
                                            script:
                                            [
                                                $class: 'ScriptlerScript',
                                                scriptlerScriptId:'getTestExecutionScenarioNames.groovy',
                                                parameters:
                                                [
                                                    [name:'TestExecutionPlatformName', value: '$RERUN_TEST_EXECUTION_PLATFORM_NAME'],
                                                    [name:'TestExecutionSuiteName', value: '$RERUN_TEST_EXECUTION_SUITE_NAME']
                                                ]
                                            ]
                                        ],
                                        [
                                            $class: 'CascadeChoiceParameter',
                                            choiceType: 'PT_MULTI_SELECT',
                                            description: 'Select the scenario scripts from the list for data insertion',
                                            filterLength: 1,
                                            filterable: true,
                                            name: 'RERUN_TEST_EXECUTION_SCENARIO_SCRIPT_NAME',
                                            randomName: 'choice-parameter-3897549400235777',
                                            referencedParameters: 'RERUN_TEST_EXECUTION_PLATFORM_NAME, RERUN_TEST_EXECUTION_SUITE_NAME, RERUN_TEST_EXECUTION_SCENARIO_NAME',
                                            script:
                                            [
                                                $class: 'ScriptlerScript',
                                                scriptlerScriptId:'getTestExecutionScenarioScriptName.groovy',
                                                parameters:
                                                [
                                                    [name:'TestExecutionPlatformName', value: '$RERUN_TEST_EXECUTION_PLATFORM_NAME'],
                                                    [name:'TestExecutionSuiteName', value: '$RERUN_TEST_EXECUTION_SUITE_NAME'],
                                                    [name:'TestExecutionScenarioName', value: '$RERUN_TEST_EXECUTION_SCENARIO_NAME']
                                                ]
                                            ]
                                        ]
                                    ])

                                testExecutionParameters = populateTestExecutionParameters(
                                    testExecutionScenario.RERUN_TEST_EXECUTION_PLATFORM_NAME,
                                    testExecutionScenario.RERUN_TEST_EXECUTION_SCENARIO_SCRIPT_NAME)
                            }
                            else
                            {
                                testExecutionParameters = populateTestExecutionParameters(
                                    params.TEST_EXECUTION_PLATFORM_NAME,
                                    params.TEST_EXECUTION_SCENARIO_SCRIPT_NAME)
                            }

                            println "Test Execution Scenario Script Names: ${testExecutionParameters.TEST_EXECUTION_SCENARIO_SCRIPT_NAME}"
                            deviceFamilyFromPipeline = getDeviceFamilyFromPipeline(testExecutionParameters.TEST_EXECUTION_PLATFORM_NAME)
                            def testExecutionInjectedVariables =
                                """@{
                                        InfrastructureType = '${params.INFRASTRUCTURE_TYPE}'
                                        DevOpsDataRootDir = '${DevOpsDataRootDir}'
                                        VmPoolBaseUrl = '${VmPoolBaseUrl}'
                                        VmPoolAuthToken = '${VMPOOL_AUTH_TOKEN}'
                                        Region = '${getRegion()}'
                                        AccessKey = '${AWS_ACCESS_KEY}'
                                        SecretKey = '${AWS_SECRET_KEY}'
                                        StageName = '${STAGE_NAME}'
                                        TestExecutionResultsBaseDirectory = "${DevOpsDataRootDir}/TestExecutionResults"
                                        TraceDBScriptsDirectory = "${DevOpsDataRootDir}/TracelogDB_Scripts"
                                        TraceDBResultsDirectory = '${TraceDBResultsDir}'
                                        JMeterScriptsDirectory = "${DevOpsDataRootDir}/JMeterScripts"
                                        ConfigurationFilePath = '\$In:${EnvironmentConfigurationFileName}'
                                        StackInfoFilePath = '\$In:${StackInfoFileNameOnly}${StackInfoFileExtension}'
                                        DeviceFamilyFromPipeline = '${deviceFamilyFromPipeline}'
                                        TestExecutionPlatformName = '${testExecutionParameters.TEST_EXECUTION_PLATFORM_NAME}'
                                        TestExecutionScenarioScriptNames = '${testExecutionParameters.TEST_EXECUTION_SCENARIO_SCRIPT_NAME}'
                                        DestinationResultsDirectory = "${WORKSPACE}/${STAGE_NAME}"
                                        EnrollmentDeviceFamilies = '${params.DEVICE_FAMILIES}'
                                        DeviceCountPerSimulatorVM = '${params.DEVICE_COUNT_PER_SIMULATOR_VM}'
                                        ReconnectionTolerancePercentage = '${ReconnectionTolerancePercentage}'
                                        SnapshotManagementTimeout = '${SnapshotManagementTimeout}'
                                        SnapshotMappingFilePath = '\$In:${SnapshotMappingFileNameOnly}.${env.STAGE_NAME}${SnapshotMappingFileExtension}'
                                        ClientId = '${ARM_CLIENT_ID}'
                                        ClientSecret = '${ARM_CLIENT_SECRET}'
                                        TenantId = '${ARM_TENANT_ID}'
                                        SubscriptionId = '${ARM_SUBSCRIPTION_ID}'
                                        AzureInstanceDataDiskSkuType = '${AzureDataDiskSkuType}'
                                        AzureOsDiskSkuType = '${AzureOsDiskSkuType}'
                                        SearchServiceName = '${buildVariables.SEARCH_SERVICE_NAME}'
                                        SearchServiceDeploymentType = '${buildVariables.SEARCH_SERVICE_DEPLOYMENT_TYPE}'
                                        SearchServiceInstanceCount = '${buildVariables.SEARCH_SERVICE_INSTANCE_COUNT}'
                                        CostUsageTag = '${buildVariables.COST_USAGE_TAG}'
                                        CurrentOwnerTag = '${params.CURRENT_OWNER_TAG}'
                                        TriggeredByTag = '${LdapDetails.userEmail}'
                                        ManagerEmailTag = '${LdapDetails.managerEmail}'
                                        DataBaseSetupType = '${params.DATABASE_SETUP}'
                                    }
                                """
                            executeMultiTasks(BUILDCONFIG_FILE_PATH, testExecutionInjectedVariables, includeTags)
                        }
                    }
                }
            }
            post
            {
                always
                {
                    archiveArtifacts artifacts: "${STAGE_NAME}\\**\\*"
                    publishReports(env.STAGE_NAME, 'BuildEvents.Report.html', 'Build Report')
                    checkAndSendSanityTestResultEmail(PerformanceTestingMailingGroupId, SanityTestingEmailSubject + params.TEST_EXECUTION_PLATFORM_NAME, "${env.WORKSPACE}/${STAGE_NAME}/${SanityTestingHtmlFilePath}", env.BUILD_URL)
                }
                aborted
                {
                    script
                    {
                        sendNotification("Build aborted, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Aborted at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                        TEST_EXECUTION_FAILED = true
                    }
                }
                failure
                {
                    script
                    {
                        sendNotification("Build failed, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Failed at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                        TEST_EXECUTION_FAILED = true
                        LAST_FAILURE_STAGE = env.STAGE_NAME
                    }
                }
            }
        }
        stage('PublishArtifacts')
        {
            when
            {
                expression { (!GO_TO_DELETE_STAGE && !skipStageExecution()) || TEST_EXECUTION_FAILED }
                beforeAgent true
            }
            agent
            {
                label AgentLabel
            }
            environment
            {
                BUILDCONFIG_FILE_PATH = "${WORKSPACE}\\${ArtifactsIn}\\.ci\\PublishArtifactsStage\\PublishArtifacts.json"
            }
            steps
            {
                catchError(stageResult: 'FAILURE')
                {
                    cleanWs()
                    echo "Installing dependency scripts."
                    internalInstallPowerShellGetScripts(CommonPsGetScriptsDefinition)
                    script
                    {
                        fetchArtifacts('SetupStack', "${StackInfoFileNameOnly}${StackInfoFileExtension}", "${WORKSPACE}/${ArtifactsIn}")
                        fetchArtifacts('PrepareEnvSetup', EnvironmentConfigurationFileName, "${WORKSPACE}/${ArtifactsIn}")

                        withVault([vaultSecrets: getVaultSecrets()])
                        {
                            def publishArtifactsInjectedVariables =
                                """@{
                                        InfrastructureType = '${params.INFRASTRUCTURE_TYPE}'
                                        DevOpsDataRootDir = '${DevOpsDataRootDir}'
                                        StackInfoFilePath = '\$In:${StackInfoFileNameOnly}${StackInfoFileExtension}'
                                        TraceDBResultsDirectory = '${TraceDBResultsDir}'
                                        TestExecutionResultsBaseDirectory = "${DevOpsDataRootDir}/TestExecutionResults"
                                        UploadFilesTempLocation = '${UploadFilesTempLocation}'
                                        AwsModuleMinimumVersion = '${AwsModuleMinimumVersion}'
                                        S3BucketName = '${PerformanceS3Bucket}'
                                        KeyPrefix = "BuildArtifacts/${JOB_NAME}/${currentBuild.number}"
                                        Region = '${getRegion()}'
                                        AccessKey = '${AWS_ACCESS_KEY}'
                                        SecretKey = '${AWS_SECRET_KEY}'
                                        ArtifactoryUrl = '${PERF_ARTIFACTORY_BASE_URL}'
                                        ArtifactoryRepository = '${ArtifactoryRepository}'
                                        ArtifactoryAccessToken = '${ARTIFACTORY_ACCESS_TOKEN}'
                                        ClientId = '${ARM_CLIENT_ID}'
                                        ClientSecret = '${ARM_CLIENT_SECRET}'
                                        TenantId = '${ARM_TENANT_ID}'
                                        SubscriptionId = '${ARM_SUBSCRIPTION_ID}'
                                        ResourceGroup = '${ResourceGroup}'
                                        StorageAccountName = '${StorageAccountName}'
                                        ContainerName = '${AzureDataContainerName}'
                                        StandardBlobTier = '${StandardBlobTier}'
                                        ConfigurationFilePath = '\$In:${EnvironmentConfigurationFileName}'
                                    }
                                """
                            executeIndividualTasks(BUILDCONFIG_FILE_PATH, publishArtifactsInjectedVariables)
                        }
                    }
                }
            }
            post
            {
                always
                {
                    publishReports(env.STAGE_NAME, 'BuildEvents.Report.html', 'Build Report')
                    script
                    {
                        println "Build Artifacts Link: ${createPublishedArtifactsLink()}"
                    }
                }
                aborted
                {
                    script
                    {
                        sendNotification("Build aborted, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Aborted at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                    }
                }
                failure
                {
                    script
                    {
                        sendNotification("Build failed, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Failed at ${STAGE_NAME}")
                        GO_TO_DELETE_STAGE = true
                        LAST_FAILURE_STAGE = env.STAGE_NAME
                    }
                }
            }
        }
        stage('ConfirmStackDeletion')
        {
            agent none
            steps
            {
                script
                {
                    if(!isTriggeredByUpstreamJob(UpstreamNightlyTriggerJob) || params.UPSTREAM_DELETE_STACK_MANUALLY)
                    {
                        input message: 'Delete stack?'
                    }
                    GO_TO_DELETE_STAGE = true
                }
            }
        }
        stage('DeleteStack')
        {
            when
            {
                expression { GO_TO_DELETE_STAGE }
                beforeAgent true
            }
            agent
            {
                label AgentLabel
            }
            options
            {
                timeout(time: 180, unit: 'MINUTES')
            }
            environment
            {
                BUILDCONFIG_FILE_PATH = "${WORKSPACE}\\${ArtifactsIn}\\.ci\\DeletionStage\\Deletion.json"
            }
            steps
            {
                script
                {
                    try
                    {
                        cleanWs()
                        copySourceCode('destroyStack.zip')
                        echo "Installing dependency scripts."
                        internalInstallPowerShellGetScripts(CommonPsGetScriptsDefinition)

                        fetchArtifacts('PrepareEnvSetup', "${EnvironmentConfigurationFileName}", "${WORKSPACE}/${ArtifactsIn}")
                        withVault([vaultSecrets: getVaultSecrets()])
                        {
                            def deleteStackInjectedVariables =
                                """@{
                                        Region = '${getRegion()}'
                                        AccessKey = '${AWS_ACCESS_KEY}'
                                        SecretKey = '${AWS_SECRET_KEY}'
                                        VmPoolBaseUrl = '${VmPoolBaseUrl}'
                                        VmPoolAuthToken = '${VMPOOL_AUTH_TOKEN}'
                                        AwsMinimumVersion = '${AwsModuleMinimumVersion}'
                                        TerraformMinimumVersion = '${TerraformMinimumVersion}'
                                        TerraformWorkingDirectory = "${WORKSPACE}/${ArtifactsIn}/.ci/.infra/terraform/${params.INFRASTRUCTURE_TYPE}"
                                        TerraformThreads = '${TerraformThreads}'
                                        ConfigurationFilePath = '\$In:${EnvironmentConfigurationFileName}'
                                        ClientId = '${ARM_CLIENT_ID}'
                                        ClientSecret = '${ARM_CLIENT_SECRET}'
                                        TenantId = '${ARM_TENANT_ID}'
                                        SubscriptionId = '${ARM_SUBSCRIPTION_ID}'
                                    }
                                """
                            executeIndividualTasks(BUILDCONFIG_FILE_PATH, deleteStackInjectedVariables)

                            if (params.INFRASTRUCTURE_TYPE == 'AWS')
                            {
                                def snapshotTag = """@{Snapshot = "${ProductName}-${BRANCH_NAME}-${BUILD_NUMBER}"}"""
                                removeSnapshot(snapshotTag, "0")
                            }
                            terminateCloudResources()
                        }
                    }
                    catch(Exception e)
                    {
                        LAST_FAILURE_STAGE = env.STAGE_NAME
                        terminateCloudResources()
                        throw e
                    }
                }
            }
            post
            {
                always
                {
                    archiveArtifacts artifacts: "${STAGE_NAME}\\**\\*"
                    publishReports(env.STAGE_NAME, 'BuildEvents.Report.html', 'Build Report')
                }
                aborted
                {
                    script
                    {
                        sendNotification("Build aborted, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Aborted at ${STAGE_NAME}")
                    }
                }
                failure
                {
                    script
                    {
                        if(LAST_FAILURE_STAGE == env.STAGE_NAME)
                        {
                            sendNotification("Build failed, for more details please check ${BUILD_URL}","$JOB_NAME/${currentBuild.number} : Status -  Failed at ${STAGE_NAME}")
                        }
                    }
                }
            }
        }
    }
    post
    {
        always
        {
            triggerUpstreamJobStageDurationStatistics()
        }
    }
}
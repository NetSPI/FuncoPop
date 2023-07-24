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
In order to run the key extraction tool, you will need to have an Azure login with some role that allows access to a vulnerable Function App Storage Account. In Powershell, you will need to import the function in order to run it.

**Importing the function:**
	`Import-Module .\Invoke-AzFunctionAppTakeover.ps1`

Once imported, you can run the function:
  `Invoke-AzFunctionAppTakeover -Verbose`

The function will prompt you to select a Subscription to attack. Once it has enumerated vulnerable Storage Accounts, you will be prompted with a list of accounts to attack. Select the ones you want to attack and the function will add malicious functions to the Storage Accounts, and attempt to execute them. These malicious functions will return the decryption key for the Function App Master Key, along with Managed Identity tokens (*if available).

Required Module to install:
* <a href="https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-3.6.1">Az</a>

## Key Decryption
The easiest way to decrypt the keys returned from the PowerShell function is to run the Function App that we created to do the decryption.
### Host your own Function App to decrypt the keys
Use the following Deploy button to deploy a function app to your Azure subscription that can be used to decrypt the extracted keys.
[![Deploy to Azure](https://github.com/Azure-Samples/function-app-arm-templates/blob/main/images/deploytoazure.png?raw=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FNetSPI%2FFuncoPop%2Fazuredeploy.json)

![image](https://github.com/NetSPI/FuncoPop/assets/2163397/3e4032b9-3614-422c-88ee-55516c1acdb1)



### Related Blogs
* <a href="https://blog.netspi.com/lateral-movement-azure-app-services/">Lateral Movement in Azure App Services</a>

### Presentations
* <a href="https://github.com/NetSPI/FuncoPop">What the Function: A Deep Dive into Azure Function App Security - DEF CON 31 - Cloud Village</a>
  - <a href="https://github.com/NetSPI/FuncoPop">Slides</a>
	

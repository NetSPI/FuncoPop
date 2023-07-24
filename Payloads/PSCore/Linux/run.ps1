using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$jsonBase = @{}

# func has a MI
if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
    $mgmtTokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=https://management.azure.com&api-version=2019-08-01"
    $mgmtTokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $mgmtTokenAuthURI
    $mgmtObject = $mgmtTokenResponse
    
    $vltTokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=https://vault.azure.net&api-version=2019-08-01"
    $vltTokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $vltTokenAuthURI
    $vltObject = $vltTokenResponse
    
    $graphTokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=https://graph.microsoft.com/&api-version=2019-08-01"
    $graphTokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $graphTokenAuthURI
    $graphObect = $graphTokenResponse
}

$jsonBase.Add("clientId",$mgmtObject.client_id)
$jsonBase.Add("managementToken",$mgmtObject.access_token)
$jsonBase.Add("vaultToken",$vltObject.access_token)
$jsonBase.Add("graphToken",$graphObect.access_token)
$jsonBase.Add("decryptionKeyId",$env:AzureWebEncryptionKey)
$body = $jsonBase | ConvertTo-Json

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
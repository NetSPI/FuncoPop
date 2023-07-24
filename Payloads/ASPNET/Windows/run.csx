#r "Newtonsoft.Json"

using System;
using System.Net.Http;
using System.Net;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;

private static HttpClient httpClient = new HttpClient();

public class MetadataResponse
{
    public string access_token { get; set; }
    public string expires_on { get; set; }
    public string resource { get; set; }
    public string token_type { get; set; }
    public string client_id { get; set; }
}

public class CombinedResponse
{
    public string client_id { get; set; }
    public string management_token { get; set; }
    public string vault_token { get; set; }
    public string graph_token { get; set; }
    public string decryption_key { get; set; }
}

public static async Task<IActionResult> Run(HttpRequest req, ILogger log)
{
    log.LogInformation("C# HTTP trigger function processed a request.");

    var combinedResponse = new CombinedResponse();

    // env vars
    string identityEndpoint = System.Environment.GetEnvironmentVariable("IDENTITY_ENDPOINT");
    string identityHeader = System.Environment.GetEnvironmentVariable("IDENTITY_HEADER");
    string decryptionKeyId = System.Environment.GetEnvironmentVariable("MACHINEKEY_DecryptionKey");

    // metadata
    string apiVersion = "2019-08-01";
    string resourceURI = "https://management.azure.com";
    string vltTokenAuthURI = "https://vault.azure.net";
    string graphTokenAuthURI = "https://graph.microsoft.com";

    // MI is set
    if (!String.IsNullOrEmpty(identityEndpoint) && !String.IsNullOrEmpty(identityHeader)) {
        string mgmtURI = identityEndpoint + "?resource=" + resourceURI + "&api-version=" + apiVersion;
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, mgmtURI);
        requestMessage.Headers.Add("X-IDENTITY-HEADER", identityHeader);
        var response = await httpClient.SendAsync(requestMessage);
        var responseBody = await response.Content.ReadAsStringAsync();
        var jsonresponse = JsonConvert.DeserializeObject<MetadataResponse>(responseBody);
        combinedResponse.client_id = jsonresponse.client_id;
        combinedResponse.management_token = jsonresponse.access_token;
        
        string vaultURI = identityEndpoint + "?resource=" + vltTokenAuthURI + "&api-version=" + apiVersion;
        var requestMessagev = new HttpRequestMessage(HttpMethod.Get, vaultURI);
        requestMessagev.Headers.Add("X-IDENTITY-HEADER", identityHeader);
        var responsev = await httpClient.SendAsync(requestMessagev);
        var responseBodyv = await responsev.Content.ReadAsStringAsync();
        var jsonresponsev = JsonConvert.DeserializeObject<MetadataResponse>(responseBodyv);
        combinedResponse.vault_token = jsonresponsev.access_token;

        string graphURI = identityEndpoint + "?resource=" + graphTokenAuthURI + "&api-version=" + apiVersion;
        var requestMessageg = new HttpRequestMessage(HttpMethod.Get, graphURI);
        requestMessageg.Headers.Add("X-IDENTITY-HEADER", identityHeader);
        var responseg = await httpClient.SendAsync(requestMessageg);
        var responseBodyg = await responseg.Content.ReadAsStringAsync();
        var jsonresponseg = JsonConvert.DeserializeObject<MetadataResponse>(responseBodyg);
        combinedResponse.graph_token = jsonresponseg.access_token;
    }

    combinedResponse.decryption_key = decryptionKeyId;
    return new OkObjectResult(combinedResponse);
}
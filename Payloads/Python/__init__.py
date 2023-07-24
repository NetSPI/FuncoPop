import logging
import json
import os
from urllib.request import urlopen, Request

import azure.functions as func

def make_urllib_request(uri, headers):
    request = Request(uri, headers=headers)
    with urlopen(request, timeout=10) as response:
        resp_body = response.read()
        resp_body = json.loads(resp_body.decode('utf-8'))
    
    return resp_body

def main(req: func.HttpRequest) -> func.HttpResponse:
    combinedResponse = {}
    
    # get environment vars
    identityEndpoint = os.getenv("IDENTITY_ENDPOINT")
    identityHeader = os.getenv("IDENTITY_HEADER")
    decryptionKeyId = os.getenv("AzureWebEncryptionKey")

    # check if MI set
    if identityEndpoint is not None and identityHeader is not None:
        resourceURI  = 'https://management.azure.com'
        vaultURI = 'https://vault.azure.net'
        graphURI = 'https://graph.microsoft.com'
        apiVersion = '2019-08-01'
        headers = {"X-IDENTITY-HEADER": identityHeader}
        params = {'resource': resourceURI, 'api-version': apiVersion}

        # use if available requests
        try:
            import requests
        
            params = {'resource': resourceURI, 'api-version': apiVersion}
            mgmtTokenResponse = requests.get(identityEndpoint,headers=headers,params=params)
            mgmt_body = mgmtTokenResponse.json()

            params = {'resource': vaultURI, 'api-version': apiVersion}
            vaultTokenResponse = requests.get(identityEndpoint,headers=headers,params=params)
            vault_body = vaultTokenResponse.json()

            params = {'resource': graphURI, 'api-version': apiVersion}
            graphTokenResponse = requests.get(identityEndpoint,headers=headers,params=params)
            graph_body = graphTokenResponse.json()

        except Exception as e:
            logging.info(e)
        
        # use urllib as fallback
        mgmt = identityEndpoint + f"?resource={resourceURI}&api-version={apiVersion}"
        mgmt_body = make_urllib_request(mgmt, headers)
        combinedResponse["clientId"] = mgmt_body["client_id"]
        combinedResponse["managementToken"] = mgmt_body["access_token"]

        vault = identityEndpoint + f"?resource={vaultURI}&api-version={apiVersion}"
        vault_body = make_urllib_request(vault, headers)
        combinedResponse["vaultToken"] = vault_body["access_token"]

        graph = identityEndpoint + f"?resource={graphURI}&api-version={apiVersion}"
        graph_body = make_urllib_request(graph, headers)
        combinedResponse["graphToken"] = graph_body["access_token"]

    # always return key
    combinedResponse["decryptionKeyId"] = decryptionKeyId
    return func.HttpResponse(json.dumps(combinedResponse))
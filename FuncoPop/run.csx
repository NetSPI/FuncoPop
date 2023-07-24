#r "Newtonsoft.Json"

using Microsoft.AspNetCore.DataProtection;
using Microsoft.Azure.Web.DataProtection;
using System.Net.Http;
using System.Text;
using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;

private static HttpClient httpClient = new HttpClient();

public static async Task<IActionResult> Run(HttpRequest req, ILogger log)
{

	string key = req.Query["key"];
	string encrypteddata = req.Query["encrypteddata"];

    if(string.IsNullOrEmpty(key)){
        string responseMessageKey = @"<html>
            <head>
                <style>
                    img {
                        max-width: 100%;
                    }
                    form {
                        max-width: 100%
                    }
                    .form-element {
                        max-width: 50%;
                        margin-bottom:1em;
                    }
                    #decrypteddata {
                        background-color: lightgray;
                        padding: 1%;
                    }
                </style>
                <title>NetSPI FuncoPop</title>
            </head>
            <body>
                <h1>Welcome to the NetSPI ""FuncoPop"" (Function App Key Decryption) App!</h1>
                <img src=""https://notpayloads.blob.core.windows.net/images/FuncoPop-bg.png"" alt=""netspi"">
                <br /><br />
                <div>You are missing a Key or Encrypted Data, please enter data for the form fields below:</div>
                <br />
                <form action=""/api/FuncoPop"">
                    <div class=""form-element"">
                        <label for=""key"">Encryption Key:</label><br />
                        <input type=""text"" id=""key"" name=""key"">
                    </div>
                    <div class=""form-element"">
                        <label for=""encrypteddata"">Encrypted Data:</label><br />
                        <input type=""text"" id=""encrypteddata"" name=""encrypteddata"">
                    </div>
                    <div class=""form-element"">
                        <input type=""submit"" value=""Submit"">
                    </div>
                </form>
                <strong>Decrypted Key value:</strong><br/><br/>
                <p><span id=""decrypteddata""></span></p>
            </body>
        </html>
        ";
        return new ContentResult{
            Content = responseMessageKey, 
            ContentType="text/html"
        };
    }
    else if(string.IsNullOrEmpty(encrypteddata)){
        string responseMessageKey = @"<html>
                <head>
                    <style>
                        img {
                            max-width: 100%;
                        }
                        form {
                            max-width: 100%
                        }
                        .form-element {
                            max-width: 50%;
                            margin-bottom:1em;
                        }
                        #decrypteddata {
                            background-color: lightgray;
                            padding: 1%;
                        }
                    </style>
                    <title>NetSPI FuncoPop</title>
                </head>
                <body>
                    <h1>Welcome to the NetSPI ""FuncoPop"" (Function App Key Decryption) App!</h1>
                    <img src=""https://notpayloads.blob.core.windows.net/images/FuncoPop-bg.png"" alt=""netspi"">
                    <br /><br />
                    <div>You are missing a Key or Encrypted Data, please enter data for the form fields below:</div>
                    <br />
                    <form action=""/api/FuncoPop"">
                        <div class=""form-element"">
                            <label for=""key"">Encryption Key:</label><br />
                            <input type=""text"" id=""key"" name=""key"">
                        </div>
                        <div class=""form-element"">
                            <label for=""encrypteddata"">Encrypted Data:</label><br />
                            <input type=""text"" id=""encrypteddata"" name=""encrypteddata"">
                        </div>
                        <div class=""form-element"">
                            <input type=""submit"" value=""Submit"">
                        </div>
                    </form>
                    <strong>Decrypted Key value:</strong><br/><br/>
                    <p><span id=""decrypteddata""></span></p>
                </body>
            </html>
        ";
        return new ContentResult{
            Content = responseMessageKey, 
            ContentType="text/html"
        };
    }

    string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
    dynamic data = JsonConvert.DeserializeObject(requestBody);
	key = key ?? data?.key;
	encrypteddata = encrypteddata ?? data?.encrypteddata;

	// Set ENV for the Key
    Environment.SetEnvironmentVariable("AzureWebEncryptionKey", key);
	
	DataProtectionKeyValueConverter converter = new DataProtectionKeyValueConverter();
    string keyname = "master";
    var ikey = new Key(keyname, encrypteddata, true);

    if (ikey.IsEncrypted)
    {
        ikey = converter.ReadValue(ikey);
    }
    
	string decrypteddata = $"{ikey.Value}";

    string responseMessage = string.IsNullOrEmpty(decrypteddata)
        ? @"<html>
    <head>
        <style>
            img {
                max-width: 100%;
            }
            form {
                max-width: 100%
            }
            .form-element {
                max-width: 50%;
                margin-bottom:1em;
            }
            #decrypteddata {
                background-color: lightgray;
                padding: 1%;
            }
        </style>
        <title>NetSPI FuncoPop</title>
    </head>
    <body>
        <h1>Welcome to the NetSPI ""FuncoPop"" (Function App Key Decryption) App!</h1>
        <img src=""https://notpayloads.blob.core.windows.net/images/FuncoPop-bg.png"" alt=""netspi"">
        <br /><br />        
        <form action=""/api/FuncoPop"">
            <div class=""form-element"">
                <label for=""key"">Encryption Key:</label><br />
                <input type=""text"" id=""key"" name=""key"">
            </div>
            <div class=""form-element"">
                <label for=""encrypteddata"">Encrypted Data:</label><br />
                <input type=""text"" id=""encrypteddata"" name=""encrypteddata"">
            </div>
            <div class=""form-element"">
                <input type=""submit"" value=""Submit"">
            </div>
        </form>
        <strong>Decrypted Key value:</strong><br/><br/>
        <p><span id=""decrypteddata"">The function failed to decrypt the supplied data, please try again.</span></p>
    </body>
</html>"
                : $@"<html>
    <head>
        <style>
            img {{
                max-width: 100%;
            }}
            form {{
                max-width: 100%
            }}
            .form-element {{
                max-width: 50%;
                margin-bottom:1em;
            }}
            #decrypteddata {{
                background-color: lightgray;
                padding: 1%;
            }}
        </style>
        <title>NetSPI FuncoPop</title>
    </head>
    <body>
        <h1>Welcome to the NetSPI ""FuncoPop"" (Function App Key Decryption) App!</h1>
        <img src=""https://notpayloads.blob.core.windows.net/images/FuncoPop-bg.png"" alt=""netspi"">
        <br /><br />
        <form action=""/api/FuncoPop"">
            <div class=""form-element"">
                <label for=""key"">Encryption Key:</label><br />
                <input type=""text"" id=""key"" name=""key"">
            </div>
            <div class=""form-element"">
                <label for=""encrypteddata"">Encrypted Data:</label><br />
                <input type=""text"" id=""encrypteddata"" name=""encrypteddata"">
            </div>
            <div class=""form-element"">
                <input type=""submit"" value=""Submit"">
            </div>
        </form>
        <strong>Decrypted Key value:</strong><br/><br/>
        <p><span id=""decrypteddata"">{decrypteddata}</span></p>
    </body>
</html>";

            return new ContentResult{
                Content = responseMessage, 
                ContentType="text/html"
            };
}

class DataProtectionKeyValueConverter
{
    private readonly IDataProtector _dataProtector;

    public DataProtectionKeyValueConverter()
    {
        var provider = DataProtectionProvider.CreateAzureDataProtector();
        _dataProtector = provider.CreateProtector("function-secrets");
    }

    public Key ReadValue(Key key)
    {
        var resultKey = new Key(key.Name, null, false);
        resultKey.Value = _dataProtector.Unprotect(key.Value);
        return resultKey;
    }
}

class Key
{
    public Key()
    {
    }

    public Key(string name, string value, bool encrypted)
    {
        Name = name;
        Value = value;
        IsEncrypted = encrypted;
    }

    [JsonProperty(PropertyName = "name")]
    public string Name { get; set; }

    [JsonProperty(PropertyName = "value")]
    public string Value { get; set; }

    [JsonProperty(PropertyName = "encrypted")]
    public bool IsEncrypted { get; set; }
}

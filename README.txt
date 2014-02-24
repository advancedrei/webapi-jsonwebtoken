Add the following to your App_Start\WebApiConfig.cs file under the Register method:

config.MessageHandlers.Add(new JsonWebTokenValidationHandler
{
    Audience = "YOUR_CLIENT_ID",
    SymmetricKey = "YOUR_CLIENT_SECRET"
});
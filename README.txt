Add the following to your App_Start\WebApiConfig.cs file under the Register method:

config.MessageHandlers.Add(new JsonWebTokenValidationHandler
{
    ClientId = "YOUR_CLIENT_ID",
    ClientSecret = "YOUR_CLIENT_SECRET"
});
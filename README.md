JsonWebToken DelegatingHandler for ASP.NET WebAPI.

## Installation

    Install-Package WebApi.JsonWebToken

## Usage

Add the following to your App_Start\WebApiConfig.cs file under the Register method:

~~~csharp
config.MessageHandlers.Add(new JsonWebTokenValidationHandler
{
    Audience = "YOUR_CLIENT_ID",
    SymmetricKey = "YOUR_CLIENT_SECRET"
});
~~~

## Documentation

For information about how to use WebApi.JsonWebToken with <a href="http://auth0.com" target="_blank">auth0</a> visit our <a href="https://docs.auth0.com/webapi" target="_blank">documentation page</a>.

## License

This client library is MIT licensed.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace $rootnamespace$
{

    /// <summary>
    /// A DelegatingHandler that processes JsonWebTokens.
    /// </summary>
    public class JsonWebTokenValidationHandler : DelegatingHandler
    {

        #region Properties

        /// <summary>
        /// The ClientId from your Auth0 account.
        /// </summary>
        /// <remarks>Other authentication providers might refer to this as the Audience.</remarks>
        public string ClientId { get; set; }

        /// <summary>
        /// The ClientSecret from your Auth0 account.
        /// </summary>
        /// <remarks>Other authentication providers might refer to this as the SymmetricKey.</remarks>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Identifies the principal that issued the JWT.
        /// </summary>
        public string Issuer { get; set; }

        #endregion

        #region DelegatingHandler Implementation

        /// <summary>
        /// Processes the incoming message.
        /// </summary>
        /// <param name="request">The current HttpRequestMessage.</param>
        /// <param name="cancellationToken">A token allowing this request to be cancelled.</param>
        /// <returns></returns>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string token;
            HttpResponseMessage errorResponse = null;

            if (TryRetrieveToken(request, out token))
            {
                try
                {
                    var secret = ClientSecret.Replace('-', '+').Replace('_', '/');

                    Thread.CurrentPrincipal = JsonWebToken.ValidateToken(token, secret, ClientId, true, Issuer);
                    
                    if (HttpContext.Current != null)
                    {
                        HttpContext.Current.User = Thread.CurrentPrincipal;
                    }
                }
                catch (JWT.SignatureVerificationException ex)
                {
                    errorResponse = request.CreateErrorResponse(HttpStatusCode.Unauthorized, ex);
                }
                catch (JsonWebToken.TokenValidationException ex)
                {
                    errorResponse = request.CreateErrorResponse(HttpStatusCode.Unauthorized, ex);
                }
                catch (Exception ex)
                {
                    errorResponse = request.CreateErrorResponse(HttpStatusCode.InternalServerError, ex);
                }
            }

            return errorResponse != null ?
                Task.FromResult(errorResponse) :
                base.SendAsync(request, cancellationToken);
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Attempts to retrieve the token from the message.
        /// </summary>
        /// <param name="request">The <see cref="HttpRequestMessage"/> to try to retrieve the token from.</param>
        /// <param name="token">The token retrieved from the message headers.</param>
        /// <returns>A boolean indicating whether or not the attempt was successful.</returns>
        private static bool TryRetrieveToken(HttpRequestMessage request, out string token)
        {
            token = null;
            IEnumerable<string> authzHeaders;

            if (!request.Headers.TryGetValues("Authorization", out authzHeaders) || authzHeaders.Count() > 1)
            {
                // Fail if no Authorization header or more than one Authorization headers  
                // are found in the HTTP request  
                return false;
            }

            // Remove the bearer token scheme prefix and return the rest as ACS token  
            var bearerToken = authzHeaders.ElementAt(0);
            token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;

            return true;
        }

        #endregion

    }

}

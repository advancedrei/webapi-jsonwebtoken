using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Script.Serialization;

namespace $rootnamespace$
{

    /// <summary>
    /// JSON Web Token (JWT) is a means of representing claims to be transferred between two parties. 
    /// The claims in a JWT are encoded as a JSON object that is digitally signed or MACed using JSON 
    /// Web Signature (JWS) and/or encrypted using JSON Web Encryption (JWE).
    /// </summary>
    public static class JsonWebToken
    {

        #region Constants

        private const string DefaultIssuer = "LOCAL AUTHORITY";

        #endregion

        #region Private Members

        private static readonly JavaScriptSerializer JsonSerializer = new JavaScriptSerializer();

        #endregion

        #region Public Methods

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token">The base64-encoded version of the JWT to process.</param>
        /// <param name="secretKey">Typically referred to as the "Client Secret".</param>
        /// <param name="audience">Typically referred to as the "Client ID".</param>
        /// <param name="checkExpiration">Whether or not we should check to see if the token is expired.</param>
        /// <param name="issuer">The principal that issued the JWT.</param>
        /// <returns></returns>
        public static void ValidateToken(string token, string secretKey, string audience = null, bool checkExpiration = false, string issuer = null)
        {
            var payloadJson = JWT.JsonWebToken.Decode(token, Convert.FromBase64String(secretKey));
            var payloadData = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);

            // audience check
            object aud;
            if (!string.IsNullOrEmpty(audience) && payloadData.TryGetValue("aud", out aud))
            {
                if (!aud.ToString().Equals(audience, StringComparison.Ordinal))
                {
                    throw new TokenValidationException(string.Format("Audience mismatch. Expected: '{0}' and got: '{1}'", audience, aud));
                }
            }

            // expiration check
            object exp;
            if (checkExpiration && payloadData.TryGetValue("exp", out exp))
            {
                DateTime validTo = FromUnixTime(long.Parse(exp.ToString()));
                if (DateTime.Compare(validTo, DateTime.UtcNow) <= 0)
                {
                    throw new TokenValidationException(
                        string.Format("Token is expired. Expiration: '{0}'. Current: '{1}'", validTo, DateTime.UtcNow));
                }
            }

            // issuer check
            object iss;
            if (payloadData.TryGetValue("iss", out iss))
            {
                if (!string.IsNullOrEmpty(issuer))
                {
                    if (!iss.ToString().Equals(issuer, StringComparison.Ordinal))
                    {
                        throw new TokenValidationException(
                            string.Format("Token issuer mismatch. Expected: '{0}' and got: '{1}'", issuer, iss));
                    }
                }
                else
                {
                    // if issuer is not specified, set issuer with jwt[iss]
                    issuer = iss.ToString();
                }
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Converts a Unix timestring to a .NET DateTime instance.
        /// </summary>
        /// <param name="unixTime">The Unix timestring to convert.</param>
        /// <returns>A <see cref="DateTime"/> instance from the given Unix timestring.</returns>
        private static DateTime FromUnixTime(long unixTime)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return epoch.AddSeconds(unixTime);
        }

        #endregion

        #region TokenValidationException

        /// <summary>
        /// Represents an error with validating the JSON Web Token.
        /// </summary>
        public class TokenValidationException : Exception
        {
            public TokenValidationException(string message)
                : base(message)
            {
            }
        }

        #endregion

    }
}

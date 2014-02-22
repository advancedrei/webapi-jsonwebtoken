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
        private const string StringClaimValueType = "http://www.w3.org/2001/XMLSchema#string";

        #endregion

        #region Private Members

        // sort claim types by relevance
        private static readonly string[] ClaimTypesForUserId = { "userid" };
        private static readonly string[] ClaimTypesForRoles = { "roles", "role" };
        private static readonly string[] ClaimTypesForEmail = { "emails", "email" };
        private static readonly string[] ClaimTypesForGivenName = { "givenname", "firstname"  };
        private static readonly string[] ClaimTypesForFamilyName = { "familyname", "lastname", "surname" };
        private static readonly string[] ClaimTypesForPostalCode = { "postalcode" };
        private static readonly string[] ClaimsToExclude = { "iss", "sub", "aud", "exp", "iat", "identities" };

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
        public static ClaimsPrincipal ValidateToken(string token, string secretKey, string audience = null, bool checkExpiration = false, string issuer = null)
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
            List<Claim> claims;

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

            claims = GetClaimsFromJwt(payloadData, issuer);
            return new ClaimsPrincipal(GetClaimsIdentity(claims, issuer));
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Gets a List of Claims from a given deserialized JSON token.
        /// </summary>
        /// <param name="jwtData">The deserialized JSON payload to process.</param>
        /// <param name="issuer">The principal that issued the JWT.</param>
        /// <returns>A List of Claims derived from the JWT.</returns>
        private static List<Claim> GetClaimsFromJwt(Dictionary<string, object> jwtData, string issuer)
        {
            var list = new List<Claim>();
            issuer = issuer ?? DefaultIssuer;

            foreach (var pair in jwtData)
            {
                var claimType = GetClaimType(pair.Key);
                var source = pair.Value as ArrayList;

                if (source != null)
                {
                    // Get the claim, check to make sure it hasn't already been added. This is a workaround
                    // for an issue where MicrosoftAccounts return the same e-mail address twice.
                    foreach (var innerClaim in source.Cast<object>().Select(item => new Claim(claimType, item.ToString(), StringClaimValueType, issuer, issuer))
                        .Where(innerClaim => !list.Any(c => c.Type == innerClaim.Type && c.Value == innerClaim.Value)))
                    {
                        list.Add(innerClaim);
                    }

                    continue;
                }

                var claim = new Claim(claimType, pair.Value.ToString(), StringClaimValueType, issuer, issuer);
                if (!list.Contains(claim))
                {
                    list.Add(claim);
                }
            }

            // dont include specific jwt claims
            return list.Where(c => ClaimsToExclude.All(t => t != c.Type)).ToList();
        }

        /// <summary>
        /// Gets a <see cref="ClaimsIdentity"/> properly populated with the claims from the JWT.
        /// </summary>
        /// <param name="claims">The list of claims that we've already processed.</param>
        /// <param name="issuer">The principal that issued the JWT.</param>
        /// <returns></returns>
        private static ClaimsIdentity GetClaimsIdentity(List<Claim> claims, string issuer)
        {
            var subject = new ClaimsIdentity("Federation", ClaimTypes.Name, ClaimTypes.Role);

            foreach (var claim in claims)
            {
                var type = claim.Type;
                if (type == ClaimTypes.Actor)
                {
                    if (subject.Actor != null)
                    {
                        throw new InvalidOperationException(string.Format(
                            "Jwt10401: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'", new object[] { "actor", claim.Value }));
                    }
                }

                var claim3 = new Claim(type, claim.Value, claim.ValueType, issuer, issuer, subject);
                subject.AddClaim(claim3);
            }

            return subject;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        private static string GetClaimType(string name)
        {
            var newName = name.Replace("_", "").ToLower();
            if (newName == "name")
            {
                return ClaimTypes.Name;
            }
            if (ClaimTypesForUserId.Contains(newName))
            {
                return ClaimTypes.NameIdentifier;
            }
            if (ClaimTypesForRoles.Contains(newName))
            {
                return ClaimTypes.Role;
            }
            if (ClaimTypesForEmail.Contains(newName))
            {
                return ClaimTypes.Email;
            }
            if (ClaimTypesForGivenName.Contains(newName))
            {
                return ClaimTypes.GivenName;
            }
            if (ClaimTypesForFamilyName.Contains(newName))
            {
                return ClaimTypes.Surname;
            }
            if (ClaimTypesForPostalCode.Contains(newName))
            {
                return ClaimTypes.PostalCode;
            }
            if (name == "gender")
            {
                return ClaimTypes.Gender;
            }

            return name;
        }

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

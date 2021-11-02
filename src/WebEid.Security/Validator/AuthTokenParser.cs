namespace WebEid.Security.Validator
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using Exceptions;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json.Linq;
    using Util;

    /// <summary>
    /// Parses the Web eID authentication token using the System.IdentityModel.Tokens.Jwt library.
    /// </summary>
    public class AuthTokenParser
    {
        private readonly string authToken;
        private readonly ILogger logger;
        private IEnumerable<Claim> claims;

        /// <summary>
        /// Creates an instance of AuthTokenParser
        /// </summary>
        /// <param name="authToken">the Web eID authentication token with signature</param>
        /// <param name="logger">logger instance</param>
        public AuthTokenParser(string authToken, ILogger logger)
        {
            this.authToken = authToken;
            this.logger = logger;
        }

        /// <summary>
        /// Parses the header part of the token.
        /// </summary>
        /// <returns><see cref="AuthTokenValidatorData"/> object with token header data filled in</returns>
        /// <exception cref="TokenParseException">when header parsing fails or header fields are missing or invalid</exception>
        internal AuthTokenValidatorData ParseHeaderFromTokenString()
        {
            try
            {
                var jwtHeader = ParseJwtHeaderFromTokenString(this.authToken);

                this.logger?.LogTrace("JWT header: {}", jwtHeader);

                var subjectCertificateList = GetListFieldOrThrow(jwtHeader, "x5c");

                var subjectCertificateField = subjectCertificateList.First();
                if (string.IsNullOrEmpty(subjectCertificateField))
                {
                    throw new TokenParseException("Certificate from x5c field must not be empty");
                }

                var signatureAlgorithm = GetStringFieldOrThrow(jwtHeader, "alg");

                var subjectCertificate = ParseCertificate(subjectCertificateField);

                this.logger?.LogTrace("Subject certificate: {}", subjectCertificateField);

                // Validate signature algorithm name
                signatureAlgorithm.ForName();

                return new AuthTokenValidatorData(subjectCertificate);
            }
            catch (TokenParseException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new TokenParseException(ex);
            }
        }

        internal void ValidateTokenSignature(X509Certificate certificate)
        {
            ValidateTokenSignature(this.authToken, certificate);
        }

        /// <summary>
        ///  Validates only JWT token issuer signing key
        /// </summary>
        /// <param name="authToken">the Web eID authentication token with signature</param>
        /// <param name="certificate">User certificate from x5c field of JWT token</param>
        /// <param name="allowedClockSkew"></param>
        private static void ValidateTokenSignature(string authToken,
            X509Certificate certificate)
        {
            try
            {
                var certificate2 = new X509Certificate2(certificate);
                // Don't dispose the key, see: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/1433
                var publicKey = certificate2.GetAsymmetricPublicKey();
                // Validate only issuer signing key
                var validationParameters = new TokenValidationParameters()
                {
                    ValidateLifetime = false,
                    ValidateAudience = false,
                    ValidateActor = false,
                    ValidateTokenReplay = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = false,
                    IssuerSigningKey = publicKey.CreateSecurityKeyWithoutCachingSignatureProviders(),
                    CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                };

                new JwtSecurityTokenHandler().ValidateToken(authToken, validationParameters, out _);
            }
            catch (SecurityTokenExpiredException ex)
            {
                throw new TokenExpiredException(ex);
            }
            catch (SecurityTokenInvalidSignatureException ex)
            {
                throw new TokenSignatureValidationException(ex);
            }
            catch (SecurityTokenException ex)
            {
                throw new TokenParseException(ex);
            }
        }

        private static JwtHeader ParseJwtHeaderFromTokenString(string authToken)
        {
            var tokenHeader = authToken.Substring(0, authToken.IndexOf('.'));
            return JwtHeader.Base64UrlDeserialize(tokenHeader);
        }

        private static JwtPayload ParseJwtBodyFromTokenString(string authToken)
        {
            var bodyPos = authToken.IndexOf('.') + 1;
            var tokenBody = authToken.Substring(bodyPos, authToken.IndexOf('.', bodyPos) - bodyPos);
            return JwtPayload.Base64UrlDeserialize(tokenBody);
        }

        /// <summary>
        /// Parses the body part of the token and extracts claims.
        /// </summary>
        /// <exception cref="TokenParseException">when body parsing fails.</exception>
        public void ParseClaims()
        {
            try
            {
                var jwtPayload = ParseJwtBodyFromTokenString(this.authToken);
                this.logger?.LogTrace("JWT body: {}", jwtPayload);
                this.claims = jwtPayload.Claims;
            }
            catch (Exception ex)
            {
                throw new TokenParseException(ex);
            }
        }

        /// <summary>
        /// Populates data from the body part of the token into the provided <see cref="AuthTokenValidatorData"/> object.
        /// </summary>
        /// <param name="data"><see cref="AuthTokenValidatorData"/> object that will be filled with body data</param>
        /// <exception cref="TokenParseException">when body fields are missing or invalid</exception>
        public void PopulateDataFromClaims(AuthTokenValidatorData data)
        {
            try
            {
                var nonceField = GetStringFieldOrThrow(this.claims, "nonce");

                // The "aud" field value is an array that contains the origin and may also contain site certificate fingerprint
                var audienceField = GetListFieldOrThrow(this.claims, "aud");
                var origin = audienceField[0];
                if (string.IsNullOrEmpty(origin))
                {
                    throw new TokenParseException("origin from aud field must not be empty");
                }

                data.Nonce = nonceField;
                data.Origin = origin;

                if (audienceField.Count > 1)
                {
                    var siteCertificateFingerprintField = audienceField[1];
                    if (string.IsNullOrEmpty(siteCertificateFingerprintField)
                        || !siteCertificateFingerprintField.StartsWith("urn:cert:sha-256:"))
                    {
                        throw new TokenParseException("site certificate fingerprint from aud field must start with urn:cert:sha-256:");
                    }
                    data.SiteCertificateFingerprint = siteCertificateFingerprintField;
                }
            }
            catch (TokenParseException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new TokenParseException(ex);
            }
        }

        private static string GetStringFieldOrThrow(IEnumerable<Claim> claims, string claimType)
        {
            try
            {
                var claim = claims.First(c => c != null && c.Type == claimType);
                if (string.IsNullOrEmpty(claim?.Value))
                {
                    throw new TokenParseException($"{claimType} field must be present and not empty in authentication token body");
                }

                if (!claim.ValueType.EndsWith("string"))
                {
                    throw new TokenParseException($"{claimType} field type must be string in authentication token body");
                }
                return claim?.Value;
            }
            catch (TokenParseException)
            {
                throw;
            }
            catch
            {
                throw new TokenParseException($"{claimType} field must be present and not empty in authentication token body");
            }
        }


        private static string GetStringFieldOrThrow(Dictionary<string, object> fields, string fieldName)
        {
            var fieldValue = (string)fields[fieldName];
            if (string.IsNullOrEmpty(fieldValue))
            {
                throw new TokenParseException($"{fieldName} field must be present and not empty in authentication token header");
            }
            return fieldValue;
        }

        private static List<string> GetListFieldOrThrow(Dictionary<string, object> fields, string fieldName)
        {
            if (!fields.ContainsKey(fieldName))
            {
                throw new TokenParseException($"{fieldName} field must be present");
            }
            if (fields[fieldName] == null)
            {
                throw new TokenParseException(
                    $"{fieldName} field in authentication token header must not be null");
            }

            IList fieldValue;
            try
            {
                fieldValue = (IList)fields[fieldName];
            }
            catch
            {
                throw new TokenParseException($"{fieldName} field in authentication token header must be an array");
            }

            if (fieldValue.Count == 0)
            {
                throw new TokenParseException($"{fieldName} field must not be empty in authentication token header");
            }

            var jsonArray = JArray.Parse(fields[fieldName].ToString());
            if (jsonArray.First().Type != JTokenType.String)
            {
                throw new TokenParseException(
                    $"{fieldName} field in authentication token header must be an array of strings, but first element is not a string");
            }

            return jsonArray.ToObject<List<string>>();
        }

        private static List<string> GetListFieldOrThrow(IEnumerable<Claim> claims, string claimType)
        {
            try
            {
                var values = claims.Where(claim => claim != null && claim.Type == claimType)
                    .Select(claim => claim.Value)
                    .ToList();
                if (values.Count == 0)
                {
                    throw new TokenParseException(
                        $"{claimType} field must be present in authentication token body and must be an array");
                }

                return values;
            }
            catch (TokenParseException)
            {
                throw;
            }
            catch
            {
                throw new TokenParseException($"{claimType} field must be present and not empty in authentication token body");
            }
        }

        private static X509Certificate ParseCertificate(string certificateInBase64)
        {
            try
            {
                var certificateBytes = Convert.FromBase64String(certificateInBase64);
                return new X509Certificate(certificateBytes);
            }
            catch (CryptographicException)
            {
                throw new TokenParseException("x5c field must contain a valid certificate");
            }
        }
    }
}

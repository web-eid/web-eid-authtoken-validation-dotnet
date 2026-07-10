// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Validator
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Exceptions;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// Provides functionality for validating the signature of an authentication token (JWT) using a specified algorithm and a public key.
    /// </summary>
    public class AuthTokenSignatureValidator
    {
        private static readonly ICollection<string> SupportedSigningAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.EcdsaSha256,
            SecurityAlgorithms.EcdsaSha384,
            SecurityAlgorithms.EcdsaSha512,
            SecurityAlgorithms.RsaSha256,
            SecurityAlgorithms.RsaSha384,
            SecurityAlgorithms.RsaSha512,
            SecurityAlgorithms.RsaSsaPssSha256,
            SecurityAlgorithms.RsaSsaPssSha384,
            SecurityAlgorithms.RsaSsaPssSha512
        };

        private readonly byte[] originBytes;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenSignatureValidator"/> class.
        /// </summary>
        /// <param name="siteOrigin">The site origin (as a Uri).</param>
        public AuthTokenSignatureValidator(Uri siteOrigin) =>
            this.originBytes = Encoding.UTF8.GetBytes(siteOrigin.OriginalString);

        /// <summary>
        /// Validates the signature of an authentication token.
        /// </summary>
        /// <param name="algorithm">The signing algorithm used for the token.</param>
        /// <param name="publicKey">The public key used for signature verification.</param>
        /// <param name="tokenSignature">The base64-encoded signature from the token.</param>
        /// <param name="currentNonce">The current nonce value.</param>
        public void Validate(string algorithm, SecurityKey publicKey, string tokenSignature, string currentNonce)
        {
            if (string.IsNullOrEmpty(currentNonce))
            { throw new ArgumentNullException(nameof(currentNonce)); }
            if (publicKey == null)
            { throw new ArgumentNullException(nameof(publicKey)); }
            RequireNotEmpty(algorithm, nameof(algorithm));
            RequireNotEmpty(tokenSignature, nameof(tokenSignature));

            var cryptoProviderFactory = publicKey.CryptoProviderFactory;
            ValidateIfAlgorithmIsSupported(algorithm, cryptoProviderFactory, publicKey);

            using var hashAlgorithm = HashAlgorithmForName(algorithm);

            var decodedSignature = Base64UrlEncoder.DecodeBytes(tokenSignature);

            var originHash = hashAlgorithm.ComputeHash(this.originBytes);
            var nonceHash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(currentNonce));
            var concatSignedFields = originHash.Concat(nonceHash).ToArray();

            using var signatureProvider = cryptoProviderFactory.CreateForVerifying(publicKey, algorithm);
            try
            {
                if (!signatureProvider.Verify(concatSignedFields, decodedSignature))
                {
                    throw new AuthTokenSignatureValidationException();
                }
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        private static void RequireNotEmpty(string algorithm, string fieldName)
        {
            if (string.IsNullOrEmpty(algorithm))
            { throw new AuthTokenParseException($"'{fieldName}' is null or empty"); }
        }

        private static void ValidateIfAlgorithmIsSupported(string algorithmName, CryptoProviderFactory cryptoProviderFactory, SecurityKey publicKey)
        {
            if (string.IsNullOrWhiteSpace(algorithmName) ||
                !SupportedSigningAlgorithms.Any(alg => alg.Equals(algorithmName, StringComparison.InvariantCultureIgnoreCase)) ||
                !cryptoProviderFactory.IsSupportedAlgorithm(algorithmName, publicKey))
            {
                throw new AuthTokenParseException("Unsupported signature algorithm");
            }
        }

        private static HashAlgorithm HashAlgorithmForName(string algorithmName)
        {
            var hashAlgorithmName = "SHA" + algorithmName[^3..];
            var hashAlgorithm = HashAlgorithm.Create(hashAlgorithmName);
            if (hashAlgorithm == null) // Should not happen as ValidateIfAlgorithmIsSupported() should assure correct algorithm name.
            { throw new NotSupportedException($"Unsupported hash algorithm '{hashAlgorithmName}'"); }
            return hashAlgorithm;
        }
    }
}

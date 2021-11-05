namespace WebEid.Security.Validator.Validators
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using Exceptions;
    using Microsoft.IdentityModel.Tokens;

    public class WebEidAuthTokenSignatureValidator
    {
        private readonly byte[] originHash;

        public WebEidAuthTokenSignatureValidator(Uri siteOrigin)
        {
            this.originHash = ToSha256(siteOrigin.OriginalString);
        }

        public void Validate(string algorithm, SecurityKey publicKey, string tokenSignature, string currentNonce)
        {
            if (string.IsNullOrEmpty(algorithm))
            { throw new ArgumentNullException(nameof(algorithm)); }
            if (publicKey == null)
            { throw new ArgumentNullException(nameof(publicKey)); }
            if (string.IsNullOrEmpty(tokenSignature))
            { throw new ArgumentNullException(nameof(tokenSignature)); }
            if (string.IsNullOrEmpty(currentNonce))
            { throw new ArgumentNullException(nameof(currentNonce)); }

            var cryptoProviderFactory = publicKey.CryptoProviderFactory;
            if (!cryptoProviderFactory.IsSupportedAlgorithm(algorithm, publicKey))
            {
                throw new NotSupportedException($"Unsupported algorithm '{algorithm}'");
            }

            var decodedSignature = Base64UrlEncoder.DecodeBytes(tokenSignature);

            var nonceHash = ToSha256(currentNonce);
            var concatSignedFields = this.originHash.Concat(nonceHash).ToArray();

            var signatureProvider = cryptoProviderFactory.CreateForVerifying(publicKey, algorithm);
            try
            {
                if (!signatureProvider.Verify(concatSignedFields, decodedSignature))
                {
                    throw new TokenSignatureValidationException();
                }
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        private static byte[] ToSha256(string data)
        {
            using (var sha256Hash = SHA256.Create())
            {
                return sha256Hash.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
            }
        }
    }
}

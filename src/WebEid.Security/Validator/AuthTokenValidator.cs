namespace WebEid.Security.Validator
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Tokens;
    using Ocsp;
    using Ocsp.Service;
    using Validators;

    public sealed class AuthTokenValidator : IAuthTokenValidator
    {
        private readonly ILogger logger;
        private readonly AuthTokenValidationConfiguration configuration;

        private readonly ValidatorBatch simpleSubjectCertificateValidators;
        private readonly ValidatorBatch tokenBodyValidators;
        private readonly OcspClient ocspClient;
        private readonly OcspServiceProvider ocspServiceProvider;

        private const int TokenMinLength = 100;
        private const int TokenMaxLength = 10000;

        public AuthTokenValidator(AuthTokenValidationConfiguration configuration, ILogger logger = null)
        {
            this.logger = logger;
            this.configuration = configuration.Copy();

            this.simpleSubjectCertificateValidators = ValidatorBatch.CreateFrom(
                new CertificateExpiryValidator(this.logger),
                new SubjectCertificatePurposeValidator(this.logger),
                new SubjectCertificatePolicyValidator(configuration.DisallowedSubjectCertificatePolicies
                    .Select(policy => new Oid(policy))
                    .ToArray())
            );

            this.tokenBodyValidators = ValidatorBatch.CreateFrom(
                    new NonceValidator(configuration.NonceCache, this.logger),
                    new OriginValidator(configuration.SiteOrigin, this.logger)
                )
                .AddOptional(configuration.IsSiteCertificateFingerprintValidationEnabled,
                    new SiteCertificateFingerprintValidator(configuration.SiteCertificateSha256Fingerprint, this.logger)
                );

            if (configuration.IsUserCertificateRevocationCheckWithOcspEnabled)
            {
                this.ocspClient = new OcspClient(TimeSpan.FromSeconds(5), this.logger);
                this.ocspServiceProvider =
                    new OcspServiceProvider(configuration.DesignatedOcspServiceConfiguration,
                        new AiaOcspServiceConfiguration(configuration.NonceDisabledOcspUrls,
                            configuration.TrustedCaCertificates));
            }

            // Turn off caching of signature providers
            CryptoProviderFactory.DefaultCacheSignatureProviders = false;
        }

        public async Task<X509Certificate> Validate(string authToken)
        {
            if (authToken == null || authToken.Length < TokenMinLength)
            {
                throw new TokenParseException("Auth token is null or too short");
            }
            if (authToken.Length > TokenMaxLength)
            {
                throw new TokenParseException("Auth token is too long");
            }

            try
            {
                this.logger?.LogInformation("Starting token parsing and validation");
                var authTokenParser = new AuthTokenParser(authToken, this.logger);
                var actualTokenData = authTokenParser.ParseHeaderFromTokenString();

                await this.simpleSubjectCertificateValidators.ExecuteFor(actualTokenData);

                await this.GetCertTrustValidators().ExecuteFor(actualTokenData);

                authTokenParser.ValidateTokenSignature(actualTokenData.SubjectCertificate);

                authTokenParser.ParseClaims();
                authTokenParser.PopulateDataFromClaims(actualTokenData);

                await this.tokenBodyValidators.ExecuteFor(actualTokenData);

                this.logger?.LogInformation("Token parsing and validation successful");

                return actualTokenData.SubjectCertificate;
            }
            catch (Exception ex)
            {
                this.logger?.LogWarning("Token parsing and validation was interrupted:", ex);
                throw;
            }
        }

        /// <summary>
        /// Creates the certificate trust validator batch
        /// As SubjectCertificateTrustedValidator has mutable state that SubjectCertificateNotRevokedValidator depends on,
        /// they cannot be reused/cached in an instance variable in a multi-threaded environment. Hence they are
        /// re-created for each validation run for thread safety.
        /// </summary>
        /// <returns>certificate trust validator batch</returns>
        private ValidatorBatch GetCertTrustValidators()
        {
            var certTrustedValidator =
                new SubjectCertificateTrustedValidator(
                    this.configuration.TrustedCaCertificates.Select(cert => new X509Certificate2(cert)).ToArray());

            return ValidatorBatch.CreateFrom(certTrustedValidator)
                .AddOptional(this.configuration.IsUserCertificateRevocationCheckWithOcspEnabled,
                    new SubjectCertificateNotRevokedValidator(certTrustedValidator,
                        this.ocspClient,
                        this.ocspServiceProvider,
                        this.logger));
        }
    }
}

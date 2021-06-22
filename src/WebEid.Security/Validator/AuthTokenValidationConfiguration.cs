namespace WebEID.Security.Validator
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Cache;
    using Util;
    using Validators;

    public sealed class AuthTokenValidationConfiguration : IEquatable<AuthTokenValidationConfiguration>
    {
        private string siteCertificateSha256Fingerprint;

        public AuthTokenValidationConfiguration() { }

        private AuthTokenValidationConfiguration(AuthTokenValidationConfiguration other)
        {
            this.SiteOrigin = other.SiteOrigin;
            this.NonceCache = other.NonceCache;
            this.TrustedCaCertificates = new List<X509Certificate>(other.TrustedCaCertificates);
            this.IsUserCertificateRevocationCheckWithOcspEnabled = other.IsUserCertificateRevocationCheckWithOcspEnabled;
            this.OcspRequestTimeout = other.OcspRequestTimeout;
            this.AllowedClientClockSkew = other.AllowedClientClockSkew;
            this.IsSiteCertificateFingerprintValidationEnabled = other.IsSiteCertificateFingerprintValidationEnabled;
            this.SiteCertificateSha256Fingerprint = other.SiteCertificateSha256Fingerprint;
            this.DisallowedSubjectCertificatePolicies = new List<string>(other.DisallowedSubjectCertificatePolicies);
            this.NonceDisabledOcspUrls = new List<Uri>(other.NonceDisabledOcspUrls);
        }

        public Uri SiteOrigin { get; set; }

        public ICache<DateTime> NonceCache { get; set; }

        public List<X509Certificate> TrustedCaCertificates { get; } = new List<X509Certificate>();

        public bool IsUserCertificateRevocationCheckWithOcspEnabled { get; set; } = true;

        public TimeSpan OcspRequestTimeout { get; set; } = TimeSpan.FromSeconds(5);

        public TimeSpan AllowedClientClockSkew { get; set; } = TimeSpan.FromMinutes(3);

        public bool IsSiteCertificateFingerprintValidationEnabled { get; private set; }

        public string SiteCertificateSha256Fingerprint
        {
            get => this.siteCertificateSha256Fingerprint;
            set
            {
                this.IsSiteCertificateFingerprintValidationEnabled = true;
                this.siteCertificateSha256Fingerprint = value;
            }
        }

        public List<string> DisallowedSubjectCertificatePolicies { get; } = new List<string>
        {
            SubjectCertificatePolicies.EsteidSk2015MobileIdPolicyV1,
            SubjectCertificatePolicies.EsteidSk2015MobileIdPolicyV2,
            SubjectCertificatePolicies.EsteidSk2015MobileIdPolicyV3,
            SubjectCertificatePolicies.EsteidSk2015MobileIdPolicy
        };

        public List<Uri> NonceDisabledOcspUrls { get; } = new List<Uri> { OcspUrls.Esteid2015 };

        public void Validate()
        {
            RequireNonNull(this.SiteOrigin, "Origin URI");
            OriginValidator.ValidateIsOriginURL(this.SiteOrigin);

            RequireNonNull(this.NonceCache, "Nonce cache");

            if (!this.TrustedCaCertificates.Any())
            {
                throw new ArgumentException("At least one trusted certificate authority must be provided");
            }

            RequirePositiveDuration(this.OcspRequestTimeout, "OCSP request timeout");
            RequirePositiveDuration(this.AllowedClientClockSkew, "Allowed client clock skew");
            if (this.IsSiteCertificateFingerprintValidationEnabled && this.siteCertificateSha256Fingerprint == null)
            {
                throw new ArgumentException("Certificate fingerprint must not be null when site certificate fingerprint validation is enabled");
            }
        }

        private static void RequireNonNull(object argument, string fieldName)
        {
            if (argument == null)
            {
                throw new ArgumentNullException(fieldName);
            }
        }

        private static void RequirePositiveDuration(TimeSpan duration, string fieldName)
        {
            if (duration.IsNegativeOrZero())
            {
                throw new ArgumentOutOfRangeException(nameof(duration), $"{fieldName} must be greater than zero");
            }
        }

        public AuthTokenValidationConfiguration Copy()
        {
            return new AuthTokenValidationConfiguration(this);
        }

        public bool Equals(AuthTokenValidationConfiguration other)
        {
            return this.SiteOrigin.Equals(other.SiteOrigin) &&
                   this.NonceCache.Equals(other.NonceCache) &&
                   Enumerable.SequenceEqual(this.TrustedCaCertificates, other.TrustedCaCertificates) &&
                   this.IsUserCertificateRevocationCheckWithOcspEnabled.Equals(other
                       .IsUserCertificateRevocationCheckWithOcspEnabled) &&
                   this.OcspRequestTimeout.Equals(other.OcspRequestTimeout) &&
                   this.AllowedClientClockSkew.Equals(other.AllowedClientClockSkew) &&
                   this.IsSiteCertificateFingerprintValidationEnabled.Equals(other
                       .IsSiteCertificateFingerprintValidationEnabled) &&
                   Enumerable.SequenceEqual(this.DisallowedSubjectCertificatePolicies,
                       other.DisallowedSubjectCertificatePolicies) &&
                   Enumerable.SequenceEqual(this.NonceDisabledOcspUrls, other.NonceDisabledOcspUrls);
        }
    }
}

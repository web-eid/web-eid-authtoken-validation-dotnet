/*
 * Copyright © 2020-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
namespace WebEid.Security.Validator
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Ocsp.Service;
    using Util;

    /// <summary>
    /// Represents the configuration for validating authentication tokens (JWTs) in the Web eID system.
    /// </summary>
    public sealed class AuthTokenValidationConfiguration : IEquatable<AuthTokenValidationConfiguration>
    {
        internal AuthTokenValidationConfiguration() { }

        private AuthTokenValidationConfiguration(AuthTokenValidationConfiguration other)
        {
            this.SiteOrigin = other.SiteOrigin;
            this.TrustedCaCertificates = new List<X509Certificate2>(other.TrustedCaCertificates);
            this.IsUserCertificateRevocationCheckWithOcspEnabled = other.IsUserCertificateRevocationCheckWithOcspEnabled;
            this.OcspRequestTimeout = other.OcspRequestTimeout;
            this.AllowedOcspResponseTimeSkew = other.AllowedOcspResponseTimeSkew;
            this.MaxOcspResponseThisUpdateAge = other.MaxOcspResponseThisUpdateAge;
            this.DesignatedOcspServiceConfiguration = other.DesignatedOcspServiceConfiguration;
            this.DisallowedSubjectCertificatePolicies = new ReadOnlyCollection<string>(other.DisallowedSubjectCertificatePolicies);
            this.NonceDisabledOcspUrls = new List<Uri>(other.NonceDisabledOcspUrls);
        }

        /// <summary>
        /// The site origin (as a Uri).
        /// </summary>
        public Uri SiteOrigin { get; set; }

        /// <summary>
        /// The list of trusted CA certificates.
        /// </summary>
        public List<X509Certificate2> TrustedCaCertificates { get; } = new List<X509Certificate2>();

        /// <summary>
        /// A value indicating whether user certificate revocation check with OCSP is enabled.
        /// By default the revocation check is enabled.
        /// </summary>
        public bool IsUserCertificateRevocationCheckWithOcspEnabled { get; set; } = true;

        /// <summary>
        /// The OCSP request timeout.
        /// </summary>
        public TimeSpan OcspRequestTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Maximum allowed time skew for the OCSP response
        /// </summary>
        public TimeSpan AllowedOcspResponseTimeSkew { get; set; } = TimeSpan.FromMinutes(15);

        /// <summary>
        /// Maximum OCSP response ThisUpdate age.
        /// </summary>
        public TimeSpan MaxOcspResponseThisUpdateAge { get; set; } = TimeSpan.FromMinutes(2);


        /// <summary>
        /// The designated OCSP service configuration.
        /// </summary>
        public DesignatedOcspServiceConfiguration DesignatedOcspServiceConfiguration { get; internal set; }

        /// <summary>
        /// The list of disallowed subject certificate policies.
        /// </summary>
        public IList<string> DisallowedSubjectCertificatePolicies { get; } =
            new List<string>(new[]
            {
                SubjectCertificatePolicies.EsteidSk2015MobileIdPolicyV1,
                SubjectCertificatePolicies.EsteidSk2015MobileIdPolicyV2,
                SubjectCertificatePolicies.EsteidSk2015MobileIdPolicyV3,
                SubjectCertificatePolicies.EsteidSk2015MobileIdPolicy
            });

        /// <summary>
        /// The list of OCSP URLs where the nonce extension is disabled.
        /// Disable OCSP nonce extension for EstEID 2015 cards by default.
        /// </summary>
        public List<Uri> NonceDisabledOcspUrls { get; } = new List<Uri> { };


        private static void RequirePositiveTimeSpan(TimeSpan timeSpan, string fieldName)
        {
            if (timeSpan.IsNegativeOrZero())
            {
                throw new ArgumentOutOfRangeException(nameof(timeSpan), $"{fieldName} must be greater than zero");
            }
        }

        /// <summary>
        /// Checks that the configuration parameters are valid.
        /// </summary>
        /// <exception cref="ArgumentNullException">When required parameters are null</exception>
        /// <exception cref="ArgumentException">When required parameters are null</exception>
        public void Validate()
        {
            ValidateSiteOriginURL(this.SiteOrigin);

            if (!this.TrustedCaCertificates.Any())
            { throw new ArgumentException("At least one trusted certificate authority must be provided"); }

            RequirePositiveTimeSpan(this.OcspRequestTimeout, "OCSP request timeout");
            RequirePositiveTimeSpan(this.AllowedOcspResponseTimeSkew, "Allowed OCSP response time-skew");
            RequirePositiveTimeSpan(this.MaxOcspResponseThisUpdateAge, "Max OCSP response thisUpdate age");
        }

        
        /// <summary>
        /// Validates that the given URI is an origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
        /// in the form of <![CDATA[<code> <scheme> "://" <hostname> [ ":" <port> ]</code>]]>.
        /// </summary>
        /// <param name="siteOrigin">URI with origin URL</param>
        /// <exception cref="ArgumentNullException">When siteOrigin parameter is null</exception>
        /// <exception cref="ArgumentException">When the URI is not in the form of origin URL</exception>
        private static void ValidateSiteOriginURL(Uri siteOrigin)
        {
            if (siteOrigin == null)
            {
                throw new ArgumentNullException(nameof(siteOrigin));
            }

            try
            {
                // 1. Verify that the URI can be converted to absolute URL.
                if (!siteOrigin.IsAbsoluteUri)
                { throw new ArgumentException("Provided URI is not a valid URL"); }
                // 2. Verify that the URI contains only HTTPS scheme, host and optional port components.
                if (!new Uri($"https://{siteOrigin.Host}:{siteOrigin.Port}").Equals(siteOrigin))
                { throw new ArgumentException("Origin URI must only contain the HTTPS scheme, host and optional port component"); }
            }
            catch (InvalidOperationException e)
            {
                throw new ArgumentException("Provided URI is not a valid URL", e);
            }
        }

        /// <summary>
        /// Creates a copy of the current <see cref="AuthTokenValidationConfiguration"/>.
        /// </summary>
        /// <returns>A new instance with the same configuration as the original.</returns>
        public AuthTokenValidationConfiguration Copy() =>
            new AuthTokenValidationConfiguration(this);

        /// <inheritdoc/>
        public bool Equals(AuthTokenValidationConfiguration other) =>
            this.SiteOrigin.Equals(other.SiteOrigin) &&
                   Enumerable.SequenceEqual(this.TrustedCaCertificates, other.TrustedCaCertificates) &&
                   this.IsUserCertificateRevocationCheckWithOcspEnabled.Equals(other
                       .IsUserCertificateRevocationCheckWithOcspEnabled) &&
                   this.OcspRequestTimeout.Equals(other.OcspRequestTimeout) &&
                   Enumerable.SequenceEqual(this.DisallowedSubjectCertificatePolicies,
                       other.DisallowedSubjectCertificatePolicies) &&
                   Equals(this.DesignatedOcspServiceConfiguration, other.DesignatedOcspServiceConfiguration) &&
                   Enumerable.SequenceEqual(this.NonceDisabledOcspUrls, other.NonceDisabledOcspUrls);
    }
}

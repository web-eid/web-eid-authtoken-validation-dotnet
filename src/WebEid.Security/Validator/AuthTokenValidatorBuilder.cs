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
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Extensions.Logging;
    using Ocsp.Service;
    using Util;

    public class AuthTokenValidatorBuilder
    {
        private readonly ILogger logger;
        private readonly AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();

        public AuthTokenValidatorBuilder(ILogger logger = null) => this.logger = logger;

        /// <summary>
        /// Sets the expected site origin, i.e. the domain that the application is running on.
        /// Origin is a mandatory configuration parameter
        /// </summary>
        /// <param name="origin">origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
        /// in the form of <example>[scheme]://[hostname][":"port]</example></param>
        /// <returns>the builder instance for method chaining></returns>
        public AuthTokenValidatorBuilder WithSiteOrigin(Uri origin)
        {
            this.configuration.SiteOrigin = origin;
            this.logger?.LogDebug("Origin set to {0}", this.configuration.SiteOrigin);
            return this;
        }

        /// <summary>
        /// Adds the given certificates to the list of trusted subject certificate intermediate Certificate Authorities.
        /// In order for the user certificate to be considered valid, the certificate of the issuer of the user certificate
        /// must be present in this list.
        /// At least one trusted intermediate Certificate Authority must be provided as a mandatory configuration parameter.
        /// </summary>
        /// <param name="certificates">trusted intermediate Certificate Authority certificates</param>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithTrustedCertificateAuthorities(params X509Certificate2[] certificates)
        {
            this.configuration.TrustedCaCertificates.AddRange(certificates);
            this.logger?.LogDebug("Trusted intermediate certificate authorities set to {0}",
                this.configuration.TrustedCaCertificates.Select(c => c.GetSubjectCn()));
            return this;
        }

        /// <summary>
        /// Adds the given policies to the list of disallowed user certificate policies.
        /// In order for the user certificate to be considered valid, it must not contain any policies
        /// present in this list.
        /// </summary>
        /// <param name="policies">disallowed user certificate policies</param>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithDisallowedCertificatePolicies(params string[] policies)
        {
            foreach (var policy in policies)
            {
                this.configuration.DisallowedSubjectCertificatePolicies.Add(policy);
            }
            this.logger?.LogDebug("Disallowed subject certificate policies set to {0}",
                string.Join(", ", this.configuration.DisallowedSubjectCertificatePolicies));
            return this;
        }

        /// <summary>
        /// Turns off user certificate revocation check with OCSP.
        /// Turning off user certificate revocation check with OCSP is dangerous and should be used only in exceptional circumstances.
        /// By default user certificate revocation check with OCSP is turned on.
        /// </summary>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithoutUserCertificateRevocationCheckWithOcsp()
        {
            this.configuration.IsUserCertificateRevocationCheckWithOcspEnabled = false;
            this.logger?.LogDebug(
                "User certificate revocation check with OCSP is disabled, you should turn off the revocation check only in exceptional circumstances");
            return this;
        }

        /// <summary>
        /// Sets both the connection and response timeout of user certificate revocation check OCSP requests.
        /// This is an optional configuration parameter, the default is 5 seconds.
        /// </summary>
        /// <param name="ocspRequestTimeout">the duration of OCSP request connection and response timeout</param>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithOcspRequestTimeout(TimeSpan ocspRequestTimeout)
        {
            this.configuration.OcspRequestTimeout = ocspRequestTimeout;
            this.logger?.LogDebug("OCSP request timeout set to {0}.", ocspRequestTimeout);
            return this;
        }

        /// <summary>
        /// Adds the given URLs to the list of OCSP URLs for which the nonce protocol extension will be disabled.
        /// The OCSP URL is extracted from the user certificate and some OCSP services don't support the nonce extension.
        /// </summary>
        /// <param name="urls">OCSP URLs for which the nonce protocol extension will be disabled</param>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithNonceDisabledOcspUrls(params Uri[] urls)
        {
            this.configuration.NonceDisabledOcspUrls.AddRange(urls);
            this.logger?.LogDebug("OCSP URLs for which the nonce protocol extension is disabled set to {0}", this.configuration.NonceDisabledOcspUrls);
            return this;
        }

        /// <summary>
        /// Activates the provided designated OCSP service for user certificate revocation check with OCSP.
        /// The designated service is only used for checking the status of the certificates whose issuers are
        /// supported by the service, falling back to the default OCSP service access location from
        /// the certificate's AIA extension if not.
        /// </summary>
        /// <param name="serviceConfiguration">configuration of the designated OCSP service</param>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration serviceConfiguration)
        {
            this.configuration.DesignatedOcspServiceConfiguration = serviceConfiguration;
            this.logger?.LogDebug("Using designated OCSP service configuration");
            return this;
        }

        /// <summary>
        /// Validates the configuration and builds the <see cref="AuthTokenValidator"/> object with it.
        /// The returned <see cref="AuthTokenValidator"/> object is immutable/thread-safe.
        /// </summary>
        /// <returns></returns>
        public IAuthTokenValidator Build()
        {
            this.configuration.Validate();
            return new AuthTokenValidator(this.configuration, this.logger);
        }
    }
}

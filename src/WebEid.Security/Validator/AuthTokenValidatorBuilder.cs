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
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Extensions.Logging;
    using Ocsp;
    using Ocsp.Service;
    using Util;

    /// <summary>
    /// Represents a builder for configuring and creating an <see cref="AuthTokenValidator"/>.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="AuthTokenValidatorBuilder"/> class.
    /// </remarks>
    /// <param name="logger">The logger for capturing log messages (optional).</param>
    [SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "The builder passes the OCSP client to the created validator and does not own its lifetime after Build().")]
    public class AuthTokenValidatorBuilder(ILogger logger = null)
    {
        private readonly ILogger logger = logger;
        private IOcspClient ocspClient;
        private readonly AuthTokenValidationConfiguration configuration = new();

        /// <summary>
        /// Sets the expected site origin, i.e. the domain that the application is running on.
        /// Origin is a mandatory configuration parameter
        /// </summary>
        /// <param name="origin">origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
        /// in the form of <example>[scheme]://[hostname][":"port]</example></param>
        /// <returns>the builder instance for method chaining></returns>
        public AuthTokenValidatorBuilder WithSiteOrigin(Uri origin)
        {
            configuration.SiteOrigin = origin;
            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug("Origin set to {Origin}", configuration.SiteOrigin);
            }
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
            configuration.TrustedCaCertificates.AddRange(certificates);
            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug("Trusted intermediate certificate authorities set to {TrustedCaCertificates}",
                    configuration.TrustedCaCertificates.Select(c => c.GetSubjectCn()));
            }
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
                configuration.DisallowedSubjectCertificatePolicies.Add(policy);
            }
            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug("Disallowed subject certificate policies set to {Policies}",
                    string.Join(", ", configuration.DisallowedSubjectCertificatePolicies));
            }
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
            configuration.IsUserCertificateRevocationCheckWithOcspEnabled = false;
            logger?.LogDebug(
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
            configuration.OcspRequestTimeout = ocspRequestTimeout;
            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug("OCSP request timeout set to {OcspRequestTimeout}.", ocspRequestTimeout);
            }
            return this;
        }

        /// <summary>
        /// Sets the allowed time skew for OCSP response's thisUpdate and nextUpdate times.
        /// This parameter is used to allow discrepancies between the system clock and the OCSP responder's clock,
        /// which may occur due to clock drift, network delays or revocation updates that are not published in real time.
        /// This is an optional configuration parameter, the default is 15 minutes.
        /// The relatively long default is specifically chosen to account for one particular OCSP responder that used
        /// CRLs for authoritative revocation info, these CRLs were updated every 15 minutes.
        /// </summary>
        /// <param name="allowedTimeSkew">The allowed time skew</param>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithAllowedOcspResponseTimeSkew(TimeSpan allowedTimeSkew)
        {
            configuration.AllowedOcspResponseTimeSkew = allowedTimeSkew;
            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug("Allowed OCSP response time skew set to {AllowedTimeSkew}.", allowedTimeSkew);
            }
            return this;
        }

        /// <summary>
        /// Sets the maximum age of the OCSP response's thisUpdate time before it is considered too old.
        /// This is an optional configuration parameter, the default is 2 minutes.
        /// </summary>
        /// <param name="maxThisUpdateAge">The maximum age of the OCSP response's thisUpdate time</param>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithMaxOcspResponseThisUpdateAge(TimeSpan maxThisUpdateAge)
        {
            configuration.MaxOcspResponseThisUpdateAge = maxThisUpdateAge;
            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug("Maximum OCSP response thisUpdate age set to {MaxThisUpdateAge}.", maxThisUpdateAge);
            }
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
            configuration.NonceDisabledOcspUrls.AddRange(urls);
            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug(
                    "OCSP URLs for which the nonce protocol extension is disabled set to {NonceDisabledOcspUrls}",
                    configuration.NonceDisabledOcspUrls);
            }
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
            configuration.DesignatedOcspServiceConfiguration = serviceConfiguration;
            logger?.LogDebug("Using designated OCSP service configuration");
            return this;
        }

        /// <summary>
        /// Configures a custom OCSP client for user certificate revocation checking.
        /// </summary>
        /// <returns>the builder instance for method chaining</returns>
        public AuthTokenValidatorBuilder WithOcspClient(IOcspClient ocspClient)
        {
            this.ocspClient = ocspClient;
            logger?.LogDebug("Custom OCSP client configured");
            return this;
        }

        /// <summary>
        /// Validates the configuration and builds the <see cref="AuthTokenValidator"/> object with it.
        /// The returned <see cref="AuthTokenValidator"/> object is immutable/thread-safe.
        /// </summary>
        /// <returns></returns>
        public IAuthTokenValidator Build()
        {
            configuration.Validate();

            if (configuration.IsUserCertificateRevocationCheckWithOcspEnabled && ocspClient == null)
            {
                ocspClient = new OcspClient(
                configuration.OcspRequestTimeout,
                logger);
            }

            return new AuthTokenValidator(configuration, ocspClient, logger);
        }
    }
}

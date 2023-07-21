/*
 * Copyright © 2020-2023 Estonian Information System Authority
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
namespace WebEid.Security.Validator.CertValidators
{
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using Util;

    internal class SubjectCertificateExpiryValidator : ISubjectCertificateValidator
    {
        private readonly List<X509Certificate2> trustedCaCertificates;
        private readonly ILogger logger;

        public SubjectCertificateExpiryValidator(List<X509Certificate2> trustedCaCertificates, ILogger logger = null)
        {
            this.trustedCaCertificates = trustedCaCertificates;
            this.logger = logger;
        }

        /// <summary>
        /// Checks the validity of the user certificate from the authentication token
        /// and the validity of trusted CA certificates.
        /// </summary>
        /// <param name="subjectCertificate">user certificate to be validated</param>
        /// <exception cref="AuthTokenException">when a CA certificate or the user certificate is expired or not yet valid</exception>
        public Task Validate(X509Certificate2 subjectCertificate)
        {
            var now = DateTimeProvider.UtcNow;

            foreach (var cert in this.trustedCaCertificates)
            {
                cert.ValidateCertificateExpiry(now, "Trusted CA");
            }
            this.logger?.LogDebug("CA certificates are valid");

            subjectCertificate.ValidateCertificateExpiry(now, "User");
            this.logger?.LogDebug("User certificate is valid");

            return Task.CompletedTask;
        }
    }
}

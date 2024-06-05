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
namespace WebEid.Security.Validator.CertValidators
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;

    public class SubjectCertificatePurposeValidator : ISubjectCertificateValidator
    {
        private readonly ILogger logger;
        private const string ExtendedKeyUsageClientAuthentication = "1.3.6.1.5.5.7.3.2";

        /// <summary>
        /// Creates an instance of SubjectCertificatePurposeValidator
        /// </summary>
        /// <param name="logger">Logger instance to log validation result</param>
        public SubjectCertificatePurposeValidator(ILogger logger = null) => this.logger = logger;

        /// <summary>
        /// Validates that the purpose of the user certificate from the authentication token contains client authentication.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the user certificate</param>
        /// <exception cref="AuthTokenException">when the purpose of certificate does not contain client authentication</exception>
        public Task Validate(X509Certificate2 subjectCertificate)
        {
            try
            {
                var usages = subjectCertificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
                if (!usages.Any())
                {
                    throw new UserCertificateMissingPurposeException();
                }

                if (usages.SelectMany(oid => oid.EnhancedKeyUsages.OfType<Oid>())
                    .All(oid => oid.Value != ExtendedKeyUsageClientAuthentication))
                {
                    throw new UserCertificateWrongPurposeException();
                }

                this.logger?.LogDebug("User certificate can be used for client authentication.");
            }
            catch (CryptographicException ex)
            {
                throw new UserCertificateParseException(ex);
            }
            catch (ArgumentNullException ex)
            {
                throw new UserCertificateParseException(ex);
            }

            return Task.CompletedTask;
        }

    }
}

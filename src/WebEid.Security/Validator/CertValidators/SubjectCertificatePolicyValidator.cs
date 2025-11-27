/*
 * Copyright © 2020-2025 Estonian Information System Authority
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
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Security;

    public sealed class SubjectCertificatePolicyValidator : ISubjectCertificateValidator
    {
        private readonly ICollection<Oid> disallowedSubjectCertificatePolicies;
        private readonly ILogger logger;

        public SubjectCertificatePolicyValidator(ICollection<Oid> disallowedSubjectCertificatePolicies, ILogger logger)
        {
            this.disallowedSubjectCertificatePolicies = disallowedSubjectCertificatePolicies
                                                        ?? throw new ArgumentNullException(nameof(disallowedSubjectCertificatePolicies));
            this.logger = logger;
        }

        /// <summary>
        /// Validates that the user certificate policies match the configured policies.
        /// </summary>
        /// <param name="subjectCertificate">the user certificate.</param>
        /// <exception cref="UserCertificateDisallowedPolicyException">when user certificate policy does not match the configured policies.</exception>
        /// <exception cref="UserCertificateParseException">when user certificate policy is invalid.</exception>
        public Task Validate(X509Certificate2 subjectCertificate)
        {
            try
            {
                var cert = DotNetUtilities.FromX509Certificate(subjectCertificate);
                var extensionValue = cert?.GetExtensionValue(X509Extensions.CertificatePolicies);
                var certificatePolicies = CertificatePolicies.GetInstance(extensionValue?.GetOctets());
                if (certificatePolicies?.GetPolicyInformation()
                    .Any(policy =>
                        this.disallowedSubjectCertificatePolicies
                        .Any(disallowedPolicy =>
                            disallowedPolicy.Value == policy.PolicyIdentifier.Id)) ?? false)
                {
                    throw new UserCertificateDisallowedPolicyException();
                }
            }
            catch (Exception ex) when (!(ex is UserCertificateDisallowedPolicyException))
            {
                throw new UserCertificateParseException(ex);
            }
            this.logger?.LogDebug("User certificate does not contain disallowed policies.");

            return Task.CompletedTask;
        }
    }
}

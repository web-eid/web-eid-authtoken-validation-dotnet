namespace WebEID.Security.Validator.Validators
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using Exceptions;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.X509;
    using Security.Validator;

    public class SubjectCertificatePolicyValidator : IValidator
    {
        private readonly ICollection<Oid> disallowedSubjectCertificatePolicies;

        public SubjectCertificatePolicyValidator(ICollection<Oid> disallowedSubjectCertificatePolicies)
        {
            this.disallowedSubjectCertificatePolicies = disallowedSubjectCertificatePolicies
                                                        ?? throw new ArgumentNullException(nameof(disallowedSubjectCertificatePolicies));
        }

        /// <summary>
        /// Validates that the user certificate policies match the configured policies.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the user certificate.</param>
        /// <exception cref="UserCertificateDisallowedPolicyException">when user certificate policy does not match the configured policies.</exception>
        /// <exception cref="UserCertificateInvalidPolicyException">when user certificate policy is invalid.</exception>
        public void Validate(AuthTokenValidatorData actualTokenData)
        {
            try
            {
                var cert = new X509CertificateParser().ReadCertificate(actualTokenData.SubjectCertificate
                    .GetRawCertData());
                var certificatePolicies =
                    CertificatePolicies.GetInstance(cert.GetExtensionValue(X509Extensions.CertificatePolicies)
                        .GetOctets());
                if (certificatePolicies.GetPolicyInformation()
                    .Any(policy =>
                        this.disallowedSubjectCertificatePolicies.Any(disallowedPolicy =>
                            disallowedPolicy.Value == policy.PolicyIdentifier.Id)))
                {
                    throw new UserCertificateDisallowedPolicyException();
                }
            }
            catch (UserCertificateDisallowedPolicyException)
            {
                throw;
            }
            catch
            {
                throw new UserCertificateInvalidPolicyException();
            }
        }
    }
}

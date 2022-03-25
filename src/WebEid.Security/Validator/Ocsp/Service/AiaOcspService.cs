namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using Org.BouncyCastle.Security;
    using Util;

    /// <summary>
    /// An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
    /// </summary>
    internal class AiaOcspService : IOcspService
    {
        private readonly List<X509Certificate2> trustedCaCertificates;

        public AiaOcspService(AiaOcspServiceConfiguration configuration,
            Org.BouncyCastle.X509.X509Certificate certificate)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            this.AccessLocation = this.GetOcspAiaUrlFromCertificate(certificate);
            this.trustedCaCertificates = configuration.TrustedCaCertificates;
            this.DoesSupportNonce = !configuration.NonceDisabledOcspUrls.Contains(this.AccessLocation);
        }

        public bool DoesSupportNonce { get; }
        public Uri AccessLocation { get; }

        private Uri GetOcspAiaUrlFromCertificate(Org.BouncyCastle.X509.X509Certificate certificate)
        {
            if (certificate == null)
            { throw new ArgumentNullException(nameof(certificate)); }

            return certificate.GetOcspUri() ??
                   throw new UserCertificateOcspCheckFailedException("Getting the AIA OCSP responder field " +
                                                                     "from the certificate failed");
        }

        public void ValidateResponderCertificate(Org.BouncyCastle.X509.X509Certificate responderCertificate, DateTime producedAt)
        {
            try
            {
                responderCertificate.ValidateCertificateExpiry(producedAt, "AIA OCSP responder");
                // Trusted certificates validity has been already verified in ValidateCertificateExpiry().
                OcspResponseValidator.ValidateHasSigningExtension(responderCertificate);
                new X509Certificate2(DotNetUtilities.ToX509Certificate(responderCertificate))
                    .ValidateIsSignedByTrustedCa(this.trustedCaCertificates);
            }
            catch (Exception ex) when (!(ex is CertificateNotTrustedException))
            {
                throw new OcspCertificateException("Invalid certificate", ex);
            }
        }
    }
}

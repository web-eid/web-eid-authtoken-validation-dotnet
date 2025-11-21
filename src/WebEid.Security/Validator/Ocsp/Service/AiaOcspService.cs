// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
            ArgumentNullException.ThrowIfNull(configuration);

            AccessLocation = GetOcspAiaUrlFromCertificate(certificate);
            trustedCaCertificates = configuration.TrustedCaCertificates;
            DoesSupportNonce = !configuration.NonceDisabledOcspUrls.Contains(AccessLocation);
        }

        public bool DoesSupportNonce { get; }
        public Uri AccessLocation { get; }

        private static Uri GetOcspAiaUrlFromCertificate(Org.BouncyCastle.X509.X509Certificate certificate)
        {
            ArgumentNullException.ThrowIfNull(certificate);

            return certificate.GetOcspUri() ??
                   throw new UserCertificateOcspCheckFailedException("Getting the AIA OCSP responder field " +
                                                                     "from the certificate failed");
        }

        public void ValidateResponderCertificate(Org.BouncyCastle.X509.X509Certificate responderCertificate, DateTime now)
        {
            try
            {
                responderCertificate.ValidateCertificateExpiry(now, "AIA OCSP responder");
                // Trusted certificates validity has been already verified in ValidateCertificateExpiry().
                OcspResponseValidator.ValidateHasSigningExtension(responderCertificate);
                _ = new X509Certificate2(DotNetUtilities.ToX509Certificate(responderCertificate))
                    .ValidateIsValidAndSignedByTrustedCa(trustedCaCertificates);
            }
            catch (Exception ex) when (ex is not CertificateNotTrustedException and not CertificateExpiredException)
            {
                throw new OcspCertificateException("Invalid certificate", ex);
            }
        }
    }
}

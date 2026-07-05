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
namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
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
        private readonly X509Certificate2 certificateIssuerCertificate;
        private readonly ICollection<X509Certificate2> additionalIntermediateCertificates;

        /// <summary>
        /// Creates an AIA OCSP service for a single validation run of the given certificate.
        /// </summary>
        /// <param name="configuration">AIA OCSP service configuration.</param>
        /// <param name="certificate">The certificate whose revocation status the service answers for.</param>
        /// <param name="certificateIssuerCertificate">The certificate that directly issued the given certificate;
        /// the OCSP responder must be authorized by it.</param>
        /// <param name="additionalIntermediateCertificates">Untrusted, token-supplied intermediate certificates that
        /// may be needed to build the responder's certification path to a trusted CA; may be empty.</param>
        public AiaOcspService(AiaOcspServiceConfiguration configuration,
            Org.BouncyCastle.X509.X509Certificate certificate,
            X509Certificate2 certificateIssuerCertificate,
            ICollection<X509Certificate2> additionalIntermediateCertificates)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(certificateIssuerCertificate);
            ArgumentNullException.ThrowIfNull(additionalIntermediateCertificates);

            AccessLocation = GetOcspAiaUrlFromCertificate(certificate);
            trustedCaCertificates = configuration.TrustedCaCertificates;
            this.certificateIssuerCertificate = certificateIssuerCertificate;
            this.additionalIntermediateCertificates = additionalIntermediateCertificates;
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
                var certificate = new X509Certificate2(DotNetUtilities.ToX509Certificate(responderCertificate));
                // The responder certificate's validity on the current date is checked as part of the certification
                // path validation. A responder may be issued by a token-supplied intermediate that is not itself
                // trusted, so the intermediates are offered as path candidates; the path must still terminate at a
                // trusted anchor. Revocation is deliberately not checked anywhere in this path: the responder
                // certificate itself is never revocation-checked, whatever revocation policy the CA has chosen for
                // it under RFC 6960 section 4.2.2.2.1, because OCSP-checking a responder against its own service
                // would be circular; and the RepresentsSameCa checks below only accept a responder that is, or is
                // directly delegated by, the subject certificate's issuer, which this validation run has already
                // vetted while validating the subject certificate.
                var responderIssuerCertificate = certificate.ValidateIsValidAndSignedByTrustedCa(
                    "AIA OCSP responder",
                    trustedCaCertificates,
                    additionalIntermediateCertificates,
                    IntermediateRevocationCheck.Disabled,
                    now);
                // RFC 6960 section 4.2.2.2: the response must be signed by the CA that issued the subject certificate
                // or by a responder directly delegated by it; a locally configured responder is handled by
                // DesignatedOcspService. CA identity is compared by subject and public key so that equivalent
                // cross-certificates for the same CA are accepted.
                if (RepresentsSameCa(certificate, certificateIssuerCertificate))
                {
                    // The response is signed by the issuing CA itself; the OCSP-signing extended key usage is required
                    // only for delegated responder certificates.
                    return;
                }
                OcspResponseValidator.ValidateHasSigningExtension(responderCertificate);
                if (!RepresentsSameCa(responderIssuerCertificate, certificateIssuerCertificate))
                {
                    throw new CertificateNotTrustedException(certificate,
                        "OCSP responder is not authorized by the subject certificate issuer");
                }
            }
            catch (Exception ex) when (ex is not CertificateNotTrustedException
                and not CertificateExpiredException
                and not CertificateNotYetValidException
                and not OcspCertificateException)
            {
                throw new OcspCertificateException("Invalid certificate", ex);
            }
        }

        private static bool RepresentsSameCa(X509Certificate2 first, X509Certificate2 second) =>
            first.SubjectName.RawData.SequenceEqual(second.SubjectName.RawData) &&
            first.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(second.PublicKey.ExportSubjectPublicKeyInfo());
    }
}

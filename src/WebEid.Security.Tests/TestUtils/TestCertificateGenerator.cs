/*
 * Copyright © 2025-2025 Estonian Information System Authority
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
namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using BcX509 = Org.BouncyCastle.Asn1.X509;

    /// <summary>
    /// Generates ephemeral certificate hierarchies for certification-path and OCSP responder tests.
    /// Mirrors the BouncyCastle-generated fixtures of the corresponding Java tests, but builds the
    /// certificates with <see cref="CertificateRequest"/> and ECDSA keys so that they can be validated by
    /// the <see cref="System.Security.Cryptography.X509Certificates.X509Chain"/>-based library implementation.
    /// </summary>
    internal static class TestCertificateGenerator
    {
        private const string OcspSigningEku = "1.3.6.1.5.5.7.3.9";
        private const string AuthorityInformationAccessOid = "1.3.6.1.5.5.7.1.1";

        /// <summary>
        /// Generates a self-signed CA certificate that can act as a trust anchor.
        /// </summary>
        public static X509Certificate2 GenerateSelfSignedCa(string commonName,
            DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request.CreateSelfSigned(notBefore, notAfter);
        }

        /// <summary>
        /// Generates a certificate issued by the given issuer.
        /// </summary>
        /// <param name="commonName">The subject common name.</param>
        /// <param name="issuer">The issuing certificate; it must carry its private key.</param>
        /// <param name="isCa">Whether the generated certificate is a CA certificate.</param>
        /// <param name="notBefore">Start of the validity window.</param>
        /// <param name="notAfter">End of the validity window.</param>
        /// <param name="ocspSigning">Whether to add the OCSP-signing extended key usage.</param>
        /// <param name="ocspUrl">When set, adds an Authority Information Access OCSP responder URL.</param>
        /// <param name="key">When set, reuses the given key pair (used to build equivalent cross-certificates).</param>
        public static X509Certificate2 GenerateCertificate(string commonName,
            X509Certificate2 issuer,
            bool isCa,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            bool ocspSigning = false,
            string ocspUrl = null,
            ECDsa key = null)
        {
            key ??= ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
            if (isCa)
            {
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            }
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            request.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            if (ocspSigning)
            {
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension([new Oid(OcspSigningEku)], false));
            }
            if (ocspUrl != null)
            {
                var authorityInformationAccess = new BcX509.AuthorityInformationAccess(
                    new BcX509.AccessDescription(BcX509.AccessDescription.IdADOcsp,
                        new BcX509.GeneralName(BcX509.GeneralName.UniformResourceIdentifier, ocspUrl)));
                request.CertificateExtensions.Add(new X509Extension(
                    new Oid(AuthorityInformationAccessOid), authorityInformationAccess.GetDerEncoded(), false));
            }

            var serialNumber = RandomNumberGenerator.GetBytes(16);
            serialNumber[0] &= 0x7F; // Keep the serial number positive.
            // Sign with an explicit signature generator rather than the issuer-certificate Create overload: the latter
            // requires the subject validity window to nest inside the issuer's, which prevents generating a currently
            // valid leaf under an expired or not-yet-valid intermediate.
            var generator = X509SignatureGenerator.CreateForECDsa(issuer.GetECDsaPrivateKey());
            var certificate = request.Create(issuer.SubjectName, generator, notBefore, notAfter, serialNumber);
            return certificate.CopyWithPrivateKey(key);
        }
    }
}

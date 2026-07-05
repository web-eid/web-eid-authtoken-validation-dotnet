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
namespace WebEid.Security.Tests.Validator.Ocsp.Service
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using NUnit.Framework;
    using Org.BouncyCastle.Security;
    using Security.Validator.Ocsp;
    using Security.Validator.Ocsp.Service;
    using TestUtils;
    using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

    /// <summary>
    /// Ports the NFC-128 AiaOcspServiceTest: AIA responder path building through token-supplied intermediates and the
    /// authorization boundary between CA-delegated AIA responders and explicitly configured designated responders.
    /// </summary>
    /// <remarks>
    /// The .NET <see cref="AiaOcspServiceConfiguration"/> has no CRL/CertStore parameter, so it always behaves like the
    /// Java "empty store" case: under the SubjectAndPublicKey policy the non-anchor intermediate revocation check is
    /// enabled and hard-fails offline for the ephemeral certificates (which carry no OCSP/CRL distribution point). The
    /// Java scenarios that need offline revocation data to succeed under SubjectAndPublicKey are therefore covered by
    /// the unknown-status test rather than by a success assertion.
    /// </remarks>
    [TestFixture]
    public sealed class AiaOcspServiceTests
    {
        private const string OcspUrl = "http://ocsp.example/responder";

        private X509Certificate2 rootCertificate;
        private X509Certificate2 intermediateCertificate;
        private X509Certificate2 crossIntermediateCertificate;
        private X509Certificate2 impostorIntermediateCertificate;
        private X509Certificate2 impostorResponderCertificate;
        private X509Certificate2 responderCertificate;
        private X509Certificate2 noEkuResponderCertificate;
        private X509Certificate2 rootIssuedResponderCertificate;
        private X509Certificate2 siblingIntermediateCertificate;
        private X509Certificate2 siblingResponderCertificate;
        private BcX509Certificate subjectCertificate;

        private DateTime now;

        [OneTimeSetUp]
        public void SetUp()
        {
            var reference = DateTimeOffset.UtcNow;
            now = reference.UtcDateTime;
            var notBefore = reference.AddDays(-1);
            var notAfter = reference.AddDays(1);

            rootCertificate = TestCertificateGenerator.GenerateSelfSignedCa("Test Root CA", notBefore, notAfter);
            intermediateCertificate = TestCertificateGenerator.GenerateCertificate(
                "Test Intermediate CA", rootCertificate, true, notBefore, notAfter);
            // An equivalent cross-certificate for the intermediate CA: same subject and public key as
            // intermediateCertificate, but a distinct certificate (different serial). RFC 6960 authorization must accept
            // it under the SubjectAndPublicKey policy.
            crossIntermediateCertificate = TestCertificateGenerator.GenerateCertificate(
                "Test Intermediate CA", rootCertificate, true, notBefore, notAfter,
                key: intermediateCertificate.GetECDsaPrivateKey());
            // An impostor CA with the same subject name as the intermediate CA but a different key pair. A responder
            // delegated by it must not be treated as authorized by the subject certificate's issuer.
            impostorIntermediateCertificate = TestCertificateGenerator.GenerateCertificate(
                "Test Intermediate CA", rootCertificate, true, notBefore, notAfter);
            impostorResponderCertificate = TestCertificateGenerator.GenerateCertificate(
                "Impostor OCSP Responder", impostorIntermediateCertificate, false, notBefore, notAfter, ocspSigning: true);
            // The OCSP responder is delegated by the intermediate CA (RFC 6960 CA-designated responder).
            responderCertificate = TestCertificateGenerator.GenerateCertificate(
                "Test OCSP Responder", intermediateCertificate, false, notBefore, notAfter, ocspSigning: true);
            // A responder issued by the intermediate CA but without the OCSP-signing extended key usage; a delegated
            // responder must carry it.
            noEkuResponderCertificate = TestCertificateGenerator.GenerateCertificate(
                "No EKU OCSP Responder", intermediateCertificate, false, notBefore, notAfter);
            // This responder is trusted through the same root, but it is not delegated by the subject certificate's
            // issuer. It can only be used as a locally configured trusted responder (RFC 6960 section 4.2.2.2).
            rootIssuedResponderCertificate = TestCertificateGenerator.GenerateCertificate(
                "Root-Issued OCSP Responder", rootCertificate, false, notBefore, notAfter, ocspSigning: true);
            siblingIntermediateCertificate = TestCertificateGenerator.GenerateCertificate(
                "Sibling Intermediate CA", rootCertificate, true, notBefore, notAfter);
            siblingResponderCertificate = TestCertificateGenerator.GenerateCertificate(
                "Sibling OCSP Responder", siblingIntermediateCertificate, false, notBefore, notAfter, ocspSigning: true);
            // The subject certificate serves two purposes: AiaOcspService reads the AIA OCSP URL from it, and the
            // designated-responder test needs its issuer name to match intermediateCertificate's subject.
            var subject = TestCertificateGenerator.GenerateCertificate(
                "Test Subject", intermediateCertificate, false, notBefore, notAfter, ocspUrl: OcspUrl);
            subjectCertificate = DotNetUtilities.FromX509Certificate(subject);
        }

        [Test]
        public void WhenMatchingPolicyIsNotSpecifiedThenExactCertificateMatchingIsUsed()
        {
            var configuration = new AiaOcspServiceConfiguration([], [rootCertificate]);
            Assert.That(configuration.ResponderIssuerMatchingPolicy,
                Is.EqualTo(ResponderIssuerMatchingPolicy.ExactCertificate));
        }

        [Test]
        public void WhenResponderChainsViaTokenIntermediateThenValidationSucceeds()
        {
            var service = AiaServiceFor(intermediateCertificate, [intermediateCertificate]);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(responderCertificate), now), Throws.Nothing);
        }

        [Test]
        public void WhenIntermediateRevocationStatusIsUnknownThenOnlySubjectAndPublicKeyPolicyFails()
        {
            var exactService = AiaServiceFor(intermediateCertificate, [intermediateCertificate],
                ResponderIssuerMatchingPolicy.ExactCertificate);
            var subjectAndPublicKeyService = AiaServiceFor(intermediateCertificate, [intermediateCertificate],
                ResponderIssuerMatchingPolicy.SubjectAndPublicKey);

            Assert.That(() => exactService.ValidateResponderCertificate(ToBc(responderCertificate), now), Throws.Nothing);
            Assert.That(() => subjectAndPublicKeyService.ValidateResponderCertificate(ToBc(responderCertificate), now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }

        [Test]
        public void WhenResponderChainsViaTokenIntermediateButIntermediateMissingThenValidationFails()
        {
            var service = AiaServiceFor(intermediateCertificate, []);

            // Without the token-supplied intermediate, the responder -> intermediate -> root path cannot be built.
            Assert.That(() => service.ValidateResponderCertificate(ToBc(responderCertificate), now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }

        [Test]
        public void WhenResponderIssuerIsEquivalentCrossCertificateWithDefaultPolicyThenValidationFails()
        {
            // The responder still chains to the root via the real intermediate, so its issuer in the built path is
            // intermediateCertificate. The subject issuer is passed as the equivalent cross-certificate (same subject
            // and public key, different certificate), which the default exact-certificate policy must reject.
            var service = AiaServiceFor(crossIntermediateCertificate, [intermediateCertificate]);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(responderCertificate), now),
                Throws.TypeOf<CertificateNotTrustedException>()
                    .With.Message.Contains("OCSP responder is not authorized by the subject certificate issuer"));
        }

        [Test]
        public void WhenResponseIsSignedByEquivalentCrossCertificateWithDefaultPolicyThenValidationFails()
        {
            var service = AiaServiceFor(intermediateCertificate, []);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(crossIntermediateCertificate), now),
                Throws.TypeOf<CertificateNotTrustedException>()
                    .With.Message.Contains("equivalent to but not the same as the subject certificate issuer"));
        }

        [Test]
        public void WhenResponseIsSignedByEquivalentCrossCertificateWithSubjectAndPublicKeyPolicyThenValidationSucceeds()
        {
            // The cross-certificate is issued directly by the trust anchor (root), so the responder path has no
            // non-anchor intermediate to revocation-check; the SubjectAndPublicKey policy then accepts it.
            var service = AiaServiceFor(intermediateCertificate, [],
                ResponderIssuerMatchingPolicy.SubjectAndPublicKey);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(crossIntermediateCertificate), now),
                Throws.Nothing);
        }

        [Test]
        public void WhenResponderIsIssuedBySiblingIntermediateThenValidationFails()
        {
            var service = AiaServiceFor(intermediateCertificate,
                [intermediateCertificate, siblingIntermediateCertificate]);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(siblingResponderCertificate), now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }

        [TestCase(ResponderIssuerMatchingPolicy.ExactCertificate)]
        [TestCase(ResponderIssuerMatchingPolicy.SubjectAndPublicKey)]
        public void WhenResponderIssuerHasSameNameButDifferentKeyThanSubjectIssuerThenValidationFails(
            ResponderIssuerMatchingPolicy matchingPolicy)
        {
            // Under ExactCertificate the responder is rejected because its issuer is not authorized by the subject
            // certificate issuer; under SubjectAndPublicKey the impostor intermediate additionally fails the offline
            // intermediate revocation check. Either way the impostor responder is rejected.
            var service = AiaServiceFor(intermediateCertificate, [impostorIntermediateCertificate], matchingPolicy);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(impostorResponderCertificate), now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }

        [Test]
        public void WhenResponderIsIssuedByRootInsteadOfSubjectIssuerThenAiaValidationFails()
        {
            var service = AiaServiceFor(intermediateCertificate, []);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(rootIssuedResponderCertificate), now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }

        [TestCase(ResponderIssuerMatchingPolicy.ExactCertificate)]
        [TestCase(ResponderIssuerMatchingPolicy.SubjectAndPublicKey)]
        public void WhenResponseSignedByIssuingCaWithoutOcspSigningEkuThenValidationSucceeds(
            ResponderIssuerMatchingPolicy matchingPolicy)
        {
            // RFC 6960 section 4.2.2.2: a response signed by the CA that issued the subject certificate is authorized
            // by CA identity alone; the OCSP-signing extended key usage is required only for delegated responders. The
            // intermediate CA certificate does not carry the extended key usage.
            var service = AiaServiceFor(intermediateCertificate, [intermediateCertificate], matchingPolicy);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(intermediateCertificate), now), Throws.Nothing);
        }

        [Test]
        public void WhenDelegatedResponderLacksOcspSigningEkuThenValidationFails()
        {
            var service = AiaServiceFor(intermediateCertificate, [intermediateCertificate]);

            Assert.That(() => service.ValidateResponderCertificate(ToBc(noEkuResponderCertificate), now),
                Throws.TypeOf<OcspCertificateException>()
                    .With.Message.Contains(
                        "does not contain the extended key usage extension value for OCSP response signing"));
        }

        [Test]
        public void WhenRootIssuedResponderIsExplicitlyDesignatedForSubjectIssuerThenValidationSucceeds()
        {
            var designatedConfiguration = new DesignatedOcspServiceConfiguration(
                new Uri(OcspUrl), ToBc(rootIssuedResponderCertificate), [ToBc(intermediateCertificate)], true);
            var provider = new OcspServiceProvider(designatedConfiguration,
                new AiaOcspServiceConfiguration([], [rootCertificate]));
            var service = provider.GetService(subjectCertificate, intermediateCertificate, []);

            Assert.That(service, Is.InstanceOf<DesignatedOcspService>());
            Assert.That(() => service.ValidateResponderCertificate(ToBc(rootIssuedResponderCertificate), now),
                Throws.Nothing);
        }

        private AiaOcspService AiaServiceFor(X509Certificate2 certificateIssuerCertificate,
            X509Certificate2[] additionalIntermediateCertificates,
            ResponderIssuerMatchingPolicy matchingPolicy = ResponderIssuerMatchingPolicy.ExactCertificate)
        {
            var configuration = new AiaOcspServiceConfiguration([], [rootCertificate], matchingPolicy);
            return new AiaOcspService(configuration, subjectCertificate,
                certificateIssuerCertificate, additionalIntermediateCertificates);
        }

        private static BcX509Certificate ToBc(X509Certificate2 certificate) =>
            DotNetUtilities.FromX509Certificate(certificate);
    }
}

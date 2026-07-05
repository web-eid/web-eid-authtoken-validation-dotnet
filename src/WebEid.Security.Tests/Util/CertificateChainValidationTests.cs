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
namespace WebEid.Security.Tests.Util
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using NUnit.Framework;
    using Security.Util;
    using TestUtils;

    /// <summary>
    /// Ports the NFC-128 additions of the Java CertificateValidatorTest: certification-path building through
    /// token-supplied intermediates, direct-issuer return value, termination at the configured trust anchor, the
    /// certificateSubject label in validity-failure messages and the intermediate revocation check.
    /// </summary>
    [TestFixture]
    public sealed class CertificateChainValidationTests
    {
        // A single chain: root -> intermediateC -> intermediateB -> intermediateA -> leaf.
        private X509Certificate2 rootCertificate;
        private X509Certificate2 intermediateCertificateC; // signed by root
        private X509Certificate2 intermediateCertificateB; // signed by C
        private X509Certificate2 intermediateCertificateA; // signed by B, direct issuer of the leaf
        private X509Certificate2 leafCertificate;          // signed by A

        private DateTime now;
        private DateTimeOffset notBefore;
        private DateTimeOffset notAfter;

        [OneTimeSetUp]
        public void SetUp()
        {
            var reference = DateTimeOffset.UtcNow;
            now = reference.UtcDateTime;
            notBefore = reference.AddDays(-1);
            notAfter = reference.AddDays(1);

            rootCertificate = TestCertificateGenerator.GenerateSelfSignedCa("Test Root CA", notBefore, notAfter);
            intermediateCertificateC = TestCertificateGenerator.GenerateCertificate(
                "Test Intermediate CA C", rootCertificate, true, notBefore, notAfter);
            intermediateCertificateB = TestCertificateGenerator.GenerateCertificate(
                "Test Intermediate CA B", intermediateCertificateC, true, notBefore, notAfter);
            intermediateCertificateA = TestCertificateGenerator.GenerateCertificate(
                "Test Intermediate CA A", intermediateCertificateB, true, notBefore, notAfter);
            leafCertificate = TestCertificateGenerator.GenerateCertificate(
                "Test Leaf", intermediateCertificateA, false, notBefore, notAfter);
        }

        [Test]
        public void WhenChainHasTokenSuppliedIntermediatesThenReturnsDirectIssuerNotTrustAnchor()
        {
            var issuer = leafCertificate.ValidateIsValidAndSignedByTrustedCa(
                "User",
                [rootCertificate],
                [intermediateCertificateA, intermediateCertificateB, intermediateCertificateC],
                IntermediateRevocationCheck.Disabled,
                now);

            // The leaf is issued by intermediate A, whose chain (A -> B -> C) leads to the root trust anchor. The
            // issuer used for OCSP must be the direct issuer (intermediate A), not the trust anchor (the root).
            Assert.That(issuer.Thumbprint, Is.EqualTo(intermediateCertificateA.Thumbprint));
        }

        [Test]
        public void WhenSubjectIssuedDirectlyByTrustAnchorThenReturnsTrustAnchor()
        {
            var issuer = leafCertificate.ValidateIsValidAndSignedByTrustedCa(
                "User",
                [intermediateCertificateA],
                [],
                IntermediateRevocationCheck.Disabled,
                now);

            // Single-hop chain: the direct issuer is the trust anchor itself.
            Assert.That(issuer.Thumbprint, Is.EqualTo(intermediateCertificateA.Thumbprint));
        }

        [Test]
        public void WhenChainHasMultipleTokenSuppliedIntermediatesAndGrandparentIsPinnedThenValidationSucceeds()
        {
            // The token supplies the full A -> B -> C intermediate chain and the top (C) is configured as the trust
            // anchor. The path builds leaf -> A -> B -> C, and the issuer returned for OCSP is the direct issuer (A).
            var issuer = leafCertificate.ValidateIsValidAndSignedByTrustedCa(
                "User",
                [intermediateCertificateC],
                [intermediateCertificateA, intermediateCertificateB, intermediateCertificateC],
                IntermediateRevocationCheck.Disabled,
                now);

            Assert.That(issuer.Thumbprint, Is.EqualTo(intermediateCertificateA.Thumbprint));
        }

        [Test]
        public void WhenTokenSuppliedIntermediateRevocationStatusIsUnknownThenRejectsCertificateChain()
        {
            // With the intermediate revocation check enabled, the non-anchor intermediates A and B must have a
            // determinable revocation status. The ephemeral certificates carry no OCSP or CRL distribution point, so
            // the hard-fail online revocation check cannot establish their status and the chain is rejected. This is
            // the offline-portable counterpart of the Java test that revokes an intermediate through a CRL.
            Assert.That(() => leafCertificate.ValidateIsValidAndSignedByTrustedCa(
                    "User",
                    [rootCertificate],
                    [intermediateCertificateA, intermediateCertificateB, intermediateCertificateC],
                    IntermediateRevocationCheck.Enabled,
                    now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }

        [Test]
        public void WhenIntermediateRevocationPolicyIsConfiguredThenUsesFiniteRetrievalTimeout()
        {
            using var chain = new X509Chain();
            var timeout = TimeSpan.FromSeconds(7);

            X509CertificateExtensions.ConfigureIntermediateRevocationPolicy(chain.ChainPolicy, timeout, now);

            Assert.That(chain.ChainPolicy.UrlRetrievalTimeout, Is.EqualTo(timeout));
            Assert.That(chain.ChainPolicy.UrlRetrievalTimeout, Is.GreaterThan(TimeSpan.Zero));
        }

        [Test]
        public void WhenIntermediateRevocationRetrievalTimeoutIsZeroThenRejectsPolicy()
        {
            using var chain = new X509Chain();

            Assert.That(() => X509CertificateExtensions.ConfigureIntermediateRevocationPolicy(
                    chain.ChainPolicy, TimeSpan.Zero, now),
                Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void WhenCertificateExpiredThenMessageUsesProvidedSubject()
        {
            var afterExpiry = notAfter.AddDays(1).UtcDateTime;

            Assert.That(() => leafCertificate.ValidateIsValidAndSignedByTrustedCa(
                    "Signing",
                    [intermediateCertificateA],
                    [],
                    IntermediateRevocationCheck.Disabled,
                    afterExpiry),
                Throws.TypeOf<CertificateExpiredException>()
                    .With.Message.EqualTo("Signing certificate has expired"));
        }

        [Test]
        public void WhenCertificateNotYetValidThenMessageUsesProvidedSubject()
        {
            var beforeValidity = notBefore.AddDays(-1).UtcDateTime;

            Assert.That(() => leafCertificate.ValidateIsValidAndSignedByTrustedCa(
                    "Signing",
                    [intermediateCertificateA],
                    [],
                    IntermediateRevocationCheck.Disabled,
                    beforeValidity),
                Throws.TypeOf<CertificateNotYetValidException>()
                    .With.Message.EqualTo("Signing certificate is not yet valid"));
        }

        [Test]
        public void WhenTokenSuppliedChainTerminatesAtUntrustedRootThenRejectsCertificateChain()
        {
            // The token supplies a complete, internally consistent chain whose self-signed root is not a configured
            // trust anchor. Token-supplied certificates are certification-path candidates only, never trust anchors,
            // so the chain must be rejected even though every signature in it verifies.
            var rogueRoot = TestCertificateGenerator.GenerateSelfSignedCa("Rogue Root CA", notBefore, notAfter);
            var rogueIntermediate = TestCertificateGenerator.GenerateCertificate(
                "Rogue Intermediate CA", rogueRoot, true, notBefore, notAfter);
            var rogueLeaf = TestCertificateGenerator.GenerateCertificate(
                "Rogue Leaf", rogueIntermediate, false, notBefore, notAfter);

            Assert.That(() => rogueLeaf.ValidateIsValidAndSignedByTrustedCa(
                    "User",
                    [rootCertificate],
                    [rogueIntermediate, rogueRoot],
                    IntermediateRevocationCheck.Enabled,
                    now),
                Throws.TypeOf<CertificateNotTrustedException>()
                    .With.Message.EqualTo("Certificate CN=Rogue Leaf is not trusted"));
        }

        [Test]
        public void WhenTokenSuppliedIntermediateIsExpiredThenRejectsCertificateChain()
        {
            // Only the token-supplied intermediate is outside its validity window; the leaf itself is currently valid.
            var localRoot = TestCertificateGenerator.GenerateSelfSignedCa("Local Root CA", notBefore, notAfter);
            var expiredIntermediate = TestCertificateGenerator.GenerateCertificate(
                "Expired Intermediate CA", localRoot, true, notBefore.AddDays(-2), notBefore.AddDays(-1));
            var currentLeaf = TestCertificateGenerator.GenerateCertificate(
                "Current Leaf", expiredIntermediate, false, notBefore, notAfter);

            Assert.That(() => currentLeaf.ValidateIsValidAndSignedByTrustedCa(
                    "User",
                    [localRoot],
                    [expiredIntermediate],
                    IntermediateRevocationCheck.Disabled,
                    now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }

        [Test]
        public void WhenTokenSuppliedIntermediateIsNotYetValidThenRejectsCertificateChain()
        {
            // Only the token-supplied intermediate is outside its validity window; the leaf itself is currently valid.
            var localRoot = TestCertificateGenerator.GenerateSelfSignedCa("Local Root CA", notBefore, notAfter);
            var notYetValidIntermediate = TestCertificateGenerator.GenerateCertificate(
                "Not Yet Valid Intermediate CA", localRoot, true, notAfter.AddDays(1), notAfter.AddDays(2));
            var currentLeaf = TestCertificateGenerator.GenerateCertificate(
                "Current Leaf", notYetValidIntermediate, false, notBefore, notAfter);

            Assert.That(() => currentLeaf.ValidateIsValidAndSignedByTrustedCa(
                    "User",
                    [localRoot],
                    [notYetValidIntermediate],
                    IntermediateRevocationCheck.Disabled,
                    now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }

        [Test]
        public void WhenTrustAnchorIsExpiredThenRejectsCertificateChain()
        {
            // The Java test expects a CertificateExpiredException from an explicit anchor validity check. On the
            // .NET/OpenSSL X509Chain the expired anchor is part of the built path and makes the path build itself
            // fail, so the library reports it as a not-trusted certificate. Either way the expired anchor is rejected
            // while the leaf is currently valid.
            var expiredRoot = TestCertificateGenerator.GenerateSelfSignedCa(
                "Expired Root CA", notBefore.AddDays(-2), notBefore.AddDays(-1));
            var currentLeaf = TestCertificateGenerator.GenerateCertificate(
                "Current Leaf", expiredRoot, false, notBefore, notAfter);

            Assert.That(() => currentLeaf.ValidateIsValidAndSignedByTrustedCa(
                    "User",
                    [expiredRoot],
                    [],
                    IntermediateRevocationCheck.Disabled,
                    now),
                Throws.TypeOf<CertificateNotTrustedException>());
        }
    }
}

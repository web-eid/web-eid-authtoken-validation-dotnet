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
namespace WebEid.Security.Tests.Validator.Ocsp
{
    using System;
    using NUnit.Framework;
    using Org.BouncyCastle.Asn1.Ocsp;
    using Org.BouncyCastle.Ocsp;
    using Org.BouncyCastle.Security;
    using Security.Validator.Ocsp;
    using TestUtils;

    [TestFixture]
    public class OcspRequestBuiderTests
    {
        [Test]
        public void BuildWithoutCertificateIdThrowsException() =>
            Assert.Throws<ArgumentNullException>(() => new OcspRequestBuilder().Build());

        [Test]
        public void BuildWithOcspNonceAddsNonceToRequest()
        {
            var certificate = DotNetUtilities.FromX509Certificate(Certificates.CertificateLoader.LoadCertificateFromResource("ESTEID2018.cer"));
            var certificateId = new CertificateID(CertificateID.HashSha1, certificate, certificate.SerialNumber);

            var request = new OcspRequestBuilder()
                .WithCertificateId(certificateId)
                .EnableOcspNonce(true).Build();

            Assert.IsNotNull(request.RequestExtensions.GetExtension(OcspObjectIdentifiers.PkixOcspNonce));
        }
    }
}

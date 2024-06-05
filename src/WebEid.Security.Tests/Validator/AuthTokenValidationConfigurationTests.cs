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
namespace WebEid.Security.Tests.Validator
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using NUnit.Framework;
    using Org.BouncyCastle.Security;
    using Security.Validator;
    using Security.Validator.Ocsp.Service;
    using TestUtils;
    using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

    [TestFixture]
    public class AuthTokenValidationConfigurationTests
    {
        [Test]
        public void AuthTokenValidationConfigurationWithoutSiteOriginThrowsArgumentException()
        {
            var configuration = new AuthTokenValidationConfiguration();
            Assert.Throws<ArgumentNullException>(() => configuration.Validate())
                .WithMessage("Value cannot be null. (Parameter 'siteOrigin')");
        }

        [Test]
        public void AuthTokenValidationConfigurationWithInvalidSiteOriginThrowsArgumentException()
        {
            var configuration =
                new AuthTokenValidationConfiguration { SiteOrigin = new Uri("invalid", UriKind.RelativeOrAbsolute) };
            Assert.Throws<ArgumentException>(() => configuration.Validate())
                .WithMessage("Provided URI is not a valid URL");
        }

        [Test]
        public void AuthTokenValidationConfigurationWithoutTrustedCertificatesThrowsArgumentException()
        {
            var configuration = new AuthTokenValidationConfiguration
            {
                SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
            };
            Assert.Throws<ArgumentException>(() => configuration.Validate())
                .WithMessage("At least one trusted certificate authority must be provided");
        }

        [Test]
        public void AuthTokenValidationConfigurationWithZeroOcspRequestTimeoutThrowsArgumentOutOfRangeException()
        {
            var configuration = new AuthTokenValidationConfiguration
            {
                SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
            };
            configuration.TrustedCaCertificates.Add(new X509Certificate2(Array.Empty<byte>()));
            configuration.OcspRequestTimeout = TimeSpan.Zero;
            Assert.Throws<ArgumentOutOfRangeException>(() => configuration.Validate())
                .WithMessage("OCSP request timeout must be greater than zero (Parameter 'ocspRequestTimeout')");
        }

        [Test]
        public void AuthTokenValidationConfigurationWithCorrectDataDoesNotThrowException()
        {
            var configuration = new AuthTokenValidationConfiguration
            {
                SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
            };
            configuration.TrustedCaCertificates.Add(new X509Certificate2(Array.Empty<byte>()));
            Assert.DoesNotThrow(() => configuration.Validate());
        }

        [Test]
        public void AuthTokenValidationConfigurationCopyCopiesAllData()
        {
            var configuration = new AuthTokenValidationConfiguration
            {
                SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
            };
            configuration.OcspRequestTimeout = TimeSpan.FromMinutes(1);
            configuration.TrustedCaCertificates.Add(new X509Certificate2(Certificates.GetTestEsteid2015Ca()));
            configuration.TrustedCaCertificates.Add(new X509Certificate2(Certificates.GetTestEsteid2018Ca()));
            configuration.DesignatedOcspServiceConfiguration = new DesignatedOcspServiceConfiguration(
                new Uri("http://ocsp.ee"),
                DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2018Ca()),
                new List<X509Certificate>
                {
                        DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2015Ca()),
                        DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2018Ca())
                });

            var copyOfConfiguration = configuration.Copy();
            Assert.AreEqual(configuration, copyOfConfiguration);
        }
    }
}

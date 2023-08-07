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
namespace WebEid.Security.Tests.Validator
{
    using System;
    using NUnit.Framework;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Validator;

    public class AuthTokenValidatorBuilderTest
    {
        private AuthTokenValidatorBuilder builder;

        [SetUp]
        public void SetUp() => this.builder = new AuthTokenValidatorBuilder();

        [Test]
        public void WhenOriginMissingThenBuildingFails() =>
            Assert.Throws<ArgumentNullException>(() => this.builder.Build())
                .WithMessage("Value cannot be null. (Parameter 'siteOrigin')");

        [Test]
        public void WhenRootCertificateAuthorityMissingThenBuildingFails()
        {
            var authTokenValidatorBuilder = this.builder.WithSiteOrigin(new Uri("https://ria.ee"));
            Assert.Throws<ArgumentException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("At least one trusted certificate authority must be provided");
        }

        [Test]
        public void WhenOriginNotUrlThenBuildingFails()
        {
            var authTokenValidatorBuilder = this.builder.WithSiteOrigin(new Uri("c:/test"));
            Assert.Throws<UriFormatException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("Invalid URI: The hostname could not be parsed.");
        }

        [Test]
        public void WhenOriginExcessiveElementsThenBuildingFails()
        {
            var authTokenValidatorBuilder = this.builder.WithSiteOrigin(new Uri("https://ria.ee/excessive-element"));
            Assert.Throws<ArgumentException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("Origin URI must only contain the HTTPS scheme, host and optional port component");
        }

        [Test]
        public void WhenOriginProtocolHttpThenBuildingFails()
        {
            var authTokenValidatorBuilder = this.builder.WithSiteOrigin(new Uri("http://ria.ee"));
            Assert.Throws<ArgumentException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("Origin URI must only contain the HTTPS scheme, host and optional port component");
        }

        [Test]
        public void WhenOriginProtocolInvalidThenBuildingFails()
        {
            var authTokenValidatorBuilder = this.builder.WithSiteOrigin(new Uri("ria://ria.ee"));
            Assert.Throws<UriFormatException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("Invalid URI: Invalid port specified."); // Bug in Uri.CreateThis()
        }
    }
}

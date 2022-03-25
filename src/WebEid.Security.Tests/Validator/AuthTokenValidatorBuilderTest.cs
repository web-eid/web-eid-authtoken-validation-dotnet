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

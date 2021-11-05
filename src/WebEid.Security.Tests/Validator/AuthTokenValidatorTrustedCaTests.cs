namespace WebEid.Security.Tests.Validator
{
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using TestUtils;

    [TestFixture]
    public class AuthTokenValidatorTrustedCaTests : AbstractTestWithMockedDateAndCorrectNonce
    {
        private IAuthTokenValidator validator;
        [SetUp]
        protected override void SetUp()
        {
            base.SetUp();
            this.validator = AuthTokenValidators.GetAuthTokenValidatorWithWrongTrustedCa(this.Cache);
        }

        [Test]
        public void DetectUntrustedUserCertificate()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<CertificateNotTrustedException>(async () => await this.validator.Validate(Tokens.SignedTest));
#pragma warning restore CS0618
        }
    }
}

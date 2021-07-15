namespace WebEid.Security.Tests.Validator
{
    using System;
    using Exceptions;
    using Microsoft.QualityTools.Testing.Fakes;
    using NUnit.Framework;
    using TestUtils;

    [TestFixture]
    public class AuthTokenValidatorX5CTests : AbstractTestWithValidatorAndCorrectNonce
    {
        private IDisposable context;

        protected override void SetUp()
        {
            base.SetUp();
            this.context = ShimsContext.Create();
            // Authentication token is valid until 2020-04-14
            System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 9, 25, 0, 0, 0, DateTimeKind.Utc);

        }

        [TearDown]
        protected override void TearDown()
        {
            base.TearDown();
            this.context.Dispose();
        }

        [Test]
        public void TestX5CMissing()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CMissing))
                .HasMessageStartingWith("x5c field must be present");
        }

        [Test]
        public void TestX5CNotArray()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CNotArray))
                .HasMessageStartingWith("x5c field in authentication token header must be an array");
        }

        [Test]
        public void TestX5cEmpty()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CEmpty))
                .HasMessageStartingWith("Certificate from x5c field must not be empty");
        }

        [Test]
        public void TestX5CNotString()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CNotString))
                .HasMessageStartingWith("x5c field in authentication token header must be an array of strings");
        }

        [Test]
        public void TestX5CInvalidCertificate()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CInvalidCertificate))
                .HasMessageStartingWith("x5c field must contain a valid certificate");
        }

        [Test]
        public void TestX5CMissingPurposeCertificate()
        {
            Assert.ThrowsAsync<UserCertificateMissingPurposeException>(() =>
                this.Validator.Validate(Tokens.X5CMissingPurposeCertificate));
        }

        [Test]
        public void TestX5CWrongPurposeCertificate()
        {
            Assert.ThrowsAsync<UserCertificateWrongPurposeException>(
                () => this.Validator.Validate(Tokens.X5CWrongPurposeCertificate));
        }

        [Test]
        public void TestX5CWrongPolicyCertificate()
        {
            Assert.ThrowsAsync<UserCertificateDisallowedPolicyException>(() =>
                this.Validator.Validate(Tokens.X5CWrongPolicyCertificate));
        }

        [Test]
        public void TestOldMobileIdCertificate()
        {
            Assert.ThrowsAsync<UserCertificateDisallowedPolicyException>(() =>
                this.Validator.Validate(Tokens.X5COldMobileIdCertificate));
        }

        [Test]
        public void TestNewMobileIdCertificate()
        {
            Assert.ThrowsAsync<UserCertificateMissingPurposeException>(() =>
                this.Validator.Validate(Tokens.X5CNewMobileIdCertificate));
        }

        [Test]
        public void TestX5CDifferentSigningCertificate()
        {
            Assert.ThrowsAsync<TokenSignatureValidationException>(() =>
                this.Validator.Validate(Tokens.X5CDifferentSigningCertificate));
        }
    }
}

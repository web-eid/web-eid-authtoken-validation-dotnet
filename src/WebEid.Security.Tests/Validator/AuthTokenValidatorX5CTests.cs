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
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CMissing))
                .HasMessageStartingWith("x5c field must be present");
#pragma warning restore CS0618
        }

        [Test]
        public void TestX5CNotArray()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CNotArray))
                .HasMessageStartingWith("x5c field in authentication token header must be an array");
#pragma warning restore CS0618
        }

        [Test]
        public void TestX5cEmpty()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CEmpty))
                .HasMessageStartingWith("Certificate from x5c field must not be empty");
#pragma warning restore CS0618
        }

        [Test]
        public void TestX5CNotString()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CNotString))
                .HasMessageStartingWith("x5c field in authentication token header must be an array of strings");
#pragma warning restore CS0618
        }

        [Test]
        public void TestX5CInvalidCertificate()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.X5CInvalidCertificate))
                .HasMessageStartingWith("x5c field must contain a valid certificate");
#pragma warning restore CS0618
        }

        [Test]
        public void TestX5CMissingPurposeCertificate()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<UserCertificateMissingPurposeException>(() =>
                this.Validator.Validate(Tokens.X5CMissingPurposeCertificate));
#pragma warning restore CS0618
        }

        [Test]
        public void TestX5CWrongPurposeCertificate()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<UserCertificateWrongPurposeException>(
                () => this.Validator.Validate(Tokens.X5CWrongPurposeCertificate));
#pragma warning restore CS0618
        }

        [Test]
        public void TestX5CWrongPolicyCertificate()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<UserCertificateDisallowedPolicyException>(() =>
                this.Validator.Validate(Tokens.X5CWrongPolicyCertificate));
#pragma warning restore CS0618
        }

        [Test]
        public void TestOldMobileIdCertificate()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<UserCertificateDisallowedPolicyException>(() =>
                this.Validator.Validate(Tokens.X5COldMobileIdCertificate));
#pragma warning restore CS0618
        }

        [Test]
        public void TestNewMobileIdCertificate()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<UserCertificateMissingPurposeException>(() =>
                this.Validator.Validate(Tokens.X5CNewMobileIdCertificate));
#pragma warning restore CS0618
        }

        [Test]
        public void TestX5CDifferentSigningCertificate()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenSignatureValidationException>(() =>
                this.Validator.Validate(Tokens.X5CDifferentSigningCertificate));
#pragma warning restore CS0618
        }
    }
}

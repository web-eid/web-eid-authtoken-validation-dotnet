namespace WebEID.Security.Tests.Validator
{
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using Security.Validator.Validators;
    using TestUtils;

    [TestFixture]
    public class AuthTokenParserTests
    {
        [Test]
        public void PopulateDataFromClaimsFillsCorrectDataAndValidationDoesNotFailFromValidToken()
        {
            var parser = new AuthTokenParser(Tokens.Signed, null);
            var data = parser.ParseHeaderFromTokenStringAndValidateTokenSignature();
            data.ValidateCertificatePurpose();
            parser.ParseClaims();
            parser.PopulateDataFromClaims(data);
            Assert.AreEqual("12345678123456781234567812345678", data.Nonce, "Nonce");
            Assert.AreEqual("https://ria.ee", data.Origin, "Origin");
            Assert.AreEqual("urn:cert:sha-256:6f0df244e4a856b94b3b3b47582a0a51a32d674dbc7107211ed23d4bec6d9c72",
                data.SiteCertificateFingerprint, "User certificate fingerprint");
            Assert.IsNotNull(data.SubjectCertificate, "User certificate");
            Assert.IsNotNull(data.SubjectCertificate.Issuer, "User certificate issuer");
            Assert.AreEqual(
                "SERIALNUMBER=PNOEE-38001085718, G=JAAK-KRISTJAN, SN=JÕEORG, CN=\"JÕEORG,JAAK-KRISTJAN,38001085718\", C=EE",
                data.SubjectCertificate.Subject, "User certificate subject");
        }

        [Test]
        public void ParseHeaderFromTokenStringWithMissingX5CFieldThrowsTokenParseException()
        {
            var parser = new AuthTokenParser(Tokens.X5CMissing, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }

        [Test]
        public void ParseHeaderFromTokenStringWithIncorrectX5CValueThrowsTokenParseException()
        {
            var parser = new AuthTokenParser(Tokens.X5CNotString, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }

        [Test]
        public void ParseHeaderFromTokenStringWithIncorrectX5CListValueThrowsTokenParseException()
        {
            var parser = new AuthTokenParser(Tokens.X5CNotArray, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }

        [Test]
        public void ParseHeaderFromTokenStringWithX5CEmptyValueThrowsTokenParseException()
        {
            var parser = new AuthTokenParser(Tokens.X5CEmpty, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }
    }
}

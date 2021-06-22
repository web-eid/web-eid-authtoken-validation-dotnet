namespace WebEID.Security.Tests.Validator
{
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using TestUtils;

    [TestFixture]
    public class AuthTokenParserTests
    {
        private string authToken;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            this.authToken = new ResourceReader("WebEID.Security.Tests.Validator").GetBytes("AuthToken.txt")
                .ToUtf8String();
        }

        [Test]
        public void PopulateDataFromClaimsFillsCorrectDataAndValidationDoesNotFailFromValidToken()
        {
            var parser = new AuthTokenParser(this.authToken, null);
            var data = parser.ParseHeaderFromTokenStringAndValidateTokenSignature();
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
            var invalidAuthToken =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            var parser = new AuthTokenParser(invalidAuthToken, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }

        [Test]
        public void ParseHeaderFromTokenStringWithIncorrectX5CValueThrowsTokenParseException()
        {
            var invalidAuthToken =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6InNvbWUgdmFsdWUifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            var parser = new AuthTokenParser(invalidAuthToken, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }

        [Test]
        public void ParseHeaderFromTokenStringWithIncorrectX5CListValueThrowsTokenParseException()
        {
            var invalidAuthToken =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6W119.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            var parser = new AuthTokenParser(invalidAuthToken, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }

        [Test]
        public void ParseHeaderFromTokenStringWithX5CNullValueThrowsTokenParseException()
        {
            var invalidAuthToken =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6bnVsbH0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            var parser = new AuthTokenParser(invalidAuthToken, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }

        [Test]
        public void ParseHeaderFromTokenStringWithX5CListNotStringValueThrowsTokenParseException()
        {
            var invalidAuthToken =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WzFdfQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            var parser = new AuthTokenParser(invalidAuthToken, null);
            Assert.Throws<TokenParseException>(() => parser.ParseHeaderFromTokenStringAndValidateTokenSignature());
        }
    }
}

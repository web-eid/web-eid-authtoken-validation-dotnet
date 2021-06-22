namespace WebEID.Security.Tests.Validator
{
    using System.Security;
    using NUnit.Framework;
    using Security.Validator;

    [TestFixture]
    public class SignatureAlgorithmExtemsionsTests
    {
        [Test]
        public void SignatureAlgorithmForNameIsFound()
        {
            Assert.AreEqual(SignatureAlgorithm.Es384, "ES384".ForName());
        }

        [Test]
        public void SignatureAlgorithmForNameIsNotFound()
        {
            Assert.Throws<SecurityException>(() => "XYZ".ForName());
        }
    }
}

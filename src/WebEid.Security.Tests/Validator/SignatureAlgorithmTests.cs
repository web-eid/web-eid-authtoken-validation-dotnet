namespace WebEid.Security.Tests.Validator
{
    using System;
    using NUnit.Framework;
    using Security.Validator;

    [TestFixture]
    public class SignatureAlgorithmTests
    {
        [Test]
        public void WithSupportedAlgorithmValueSucceeds()
        {
            Assert.DoesNotThrow(() => SignatureAlgorithm.ValidateIfSupported("ES384"));
        }

        [Test]
        public void WithSupportedAlgorithmValueDifferentCaseSucceeds()
        {
            Assert.DoesNotThrow(() => SignatureAlgorithm.ValidateIfSupported("Es384"));
        }

        [Test]
        public void WithAlgorithmValueNoneThrows()
        {
            Assert.Throws<NotSupportedException>(() => SignatureAlgorithm.ValidateIfSupported("None"));
        }

        [Test]
        public void WithUnsupportedAlgorithmThrows()
        {
            Assert.Throws<NotSupportedException>(() => SignatureAlgorithm.ValidateIfSupported("XYZ"));
        }
    }
}

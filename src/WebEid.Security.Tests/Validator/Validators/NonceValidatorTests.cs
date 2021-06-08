namespace WebEID.Security.Tests.Validator.Validators
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Cache;
    using Exceptions;
    using NUnit.Framework;
    using Security.Nonce;
    using Security.Validator;
    using Security.Validator.Validators;

    [TestFixture]
    public class NonceValidatorTests
    {
        [Test]
        public void ValidateNonceWithWrongLengthThrowsTokenParseException()
        {
            using (var cache = new MemoryCache<DateTime?>())
            {
                var nonceKey = "nonce-key";
                cache.Put(nonceKey, DateTime.MaxValue);
                var validator = new NonceValidator(cache, null);
                Assert.Throws<TokenParseException>(() =>
                    validator.ValidateNonce(new AuthTokenValidatorData(new X509Certificate()) { Nonce = nonceKey }));
            }
        }

        [Test]
        public void ValidateNonceNotInCacheThrowsNonceNotFoundException()
        {
            using (var cache = new MemoryCache<DateTime?>())
            {
                var nonceKey = "nonce-key";
                var validator = new NonceValidator(cache, null);
                Assert.Throws<NonceNotFoundException>(() =>
                    validator.ValidateNonce(new AuthTokenValidatorData(new X509Certificate()) { Nonce = nonceKey }));
            }
        }

        [Test]
        public void ValidateExpiredNonceThrowsNonceExpiredException()
        {
            using (var cache = new MemoryCache<DateTime?>())
            {
                var nonceKey = "nonce".PadLeft(INonceGenerator.NonceLength);
                cache.Put(nonceKey, new DateTime(2000, 1, 1));
                var validator = new NonceValidator(cache, null);
                Assert.Throws<NonceExpiredException>(() =>
                    validator.ValidateNonce(new AuthTokenValidatorData(new X509Certificate()) { Nonce = nonceKey }));
            }
        }

        [Test]
        public void ValidateCorrectNonceDoesNotThrowException()
        {
            using (var cache = new MemoryCache<DateTime?>())
            {
                var nonceKey = "nonce".PadLeft(INonceGenerator.NonceLength);
                cache.Put(nonceKey, DateTime.MaxValue);
                var validator = new NonceValidator(cache, null);
                Assert.DoesNotThrow(() =>
                    validator.ValidateNonce(new AuthTokenValidatorData(new X509Certificate()) { Nonce = nonceKey }));
            }
        }
    }
}

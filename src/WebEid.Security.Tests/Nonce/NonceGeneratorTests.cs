namespace WebEid.Security.Tests.Nonce
{
    using System;
    using System.Security.Cryptography;
    using Cache;
    using NUnit.Framework;
    using Security.Nonce;

    [TestFixture]
    public class NonceGeneratorTests
    {
        [Test]
        public void NonceIsGeneratedAndCached()
        {
            using (var cache = new MemoryCache<DateTime>())
            using (var rndGenerator = RNGCryptoServiceProvider.Create())
            {
                var nonceGenerator = new NonceGeneratorBuilder()
                    .WithSecureRandom(rndGenerator)
                    .WithNonceCache(cache)
                    .Build();

                var nonce1 = nonceGenerator.GenerateAndStoreNonce();
                var nonce2 = nonceGenerator.GenerateAndStoreNonce();

                Assert.That(nonce1.Length, Is.EqualTo(44));
                Assert.That(nonce1, Is.Not.EquivalentTo(nonce2));
                // It might be possible to add an entropy test by compressing the nonce bytes
                // and verifying that the result is longer than for non-random strings.

                // Validate that generated nonces are put into cache
                Assert.True(cache.Contains(nonce1));
                Assert.True(cache.Contains(nonce2));
            }
        }

        [Test]
        public void BuildNonceGeneratorWithoutRandomNumberGeneratorThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new NonceGeneratorBuilder().WithSecureRandom(null).WithNonceCache(null).Build());
        }

        [Test]
        public void BuildNonceGeneratorWithoutCacheThrowsArgumentNullException()
        {
            using (var rndGenerator = RNGCryptoServiceProvider.Create())
            {
                Assert.Throws<ArgumentNullException>(() => new NonceGeneratorBuilder().WithSecureRandom(rndGenerator).WithNonceCache(null).Build());
            }
        }

        [Test]
        public void BuildNonceGeneratorWithNegativeTtlThrowsArgumentOutOfRangeException()
        {
            using (var rndGenerator = RNGCryptoServiceProvider.Create())
            using (var cache = new MemoryCache<DateTime>())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new NonceGeneratorBuilder().WithSecureRandom(rndGenerator).WithNonceCache(cache).WithNonceTtl(TimeSpan.FromMinutes(1).Negate()).Build());
            }
        }

        [Test]
        public void BuildNonceGeneratorWithZeroTtlThrowsArgumentOutOfRangeException()
        {
            using (var rndGenerator = RNGCryptoServiceProvider.Create())
            using (var cache = new MemoryCache<DateTime>())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => new NonceGeneratorBuilder().WithSecureRandom(rndGenerator).WithNonceCache(cache).WithNonceTtl(TimeSpan.Zero).Build());
            }
        }

        [Test]
        public void BuildNonceGeneratorWithRandomNumberGeneratorAndCacheDoesNotThrowException()
        {
            using (var rndGenerator = RNGCryptoServiceProvider.Create())
            using (var cache = new MemoryCache<DateTime>())
            {
                Assert.DoesNotThrow(() => new NonceGeneratorBuilder().WithSecureRandom(rndGenerator).WithNonceCache(cache).Build());
            }
        }

        [Test]
        public void BuildNonceGeneratorWithRandomNumberGeneratorAndCacheAndPositiveTtlDoesNotThrowException()
        {
            using (var rndGenerator = RNGCryptoServiceProvider.Create())
            using (var cache = new MemoryCache<DateTime>())
            {
                Assert.DoesNotThrow(() => new NonceGeneratorBuilder().WithSecureRandom(rndGenerator).WithNonceCache(cache).WithNonceTtl(TimeSpan.FromMinutes(1)).Build());
            }
        }
    }
}

/*
 * Copyright © 2020-2023 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
namespace WebEid.Security.Tests.Nonce
{
    using System;
    using System.Security.Cryptography;
    using NUnit.Framework;
    using Challenge;

    [TestFixture]
    public class ChallengeNonceGeneratorTests
    {
        private IChallengeNonceStore store;
        private TimeSpan ttl;

        [SetUp]
        protected void SetUp()
        {
            this.store = new InMemoryChallengeNonceStore();
            this.ttl = TimeSpan.FromMinutes(5);
        }

        [Test]
        public void NonceIsGeneratedAndStored()
        {
            using var rndGenerator = RandomNumberGenerator.Create();
            var nonceGenerator = new ChallengeNonceGenerator(rndGenerator, this.store);

            var nonce1 = nonceGenerator.GenerateAndStoreNonce(this.ttl);
            var nonce2 = nonceGenerator.GenerateAndStoreNonce(this.ttl);

            var nonce2FromStore = this.store.GetAndRemove();

            // Validate that generated nonce was put into the store.
            Assert.That(nonce2, Is.EqualTo(nonce2FromStore));

            Assert.That(nonce1.Base64EncodedNonce.Length, Is.EqualTo(44));
            Assert.That(nonce1.Base64EncodedNonce, Is.Not.EquivalentTo(nonce2.Base64EncodedNonce));

            // It might be possible to add an entropy test by compressing the nonce bytes
            // and verifying that the result is longer than for non-random strings.
        }

        [Test]
        public void BuildNonceGeneratorWithoutRandomNumberGeneratorThrowsArgumentNullException() =>
            Assert.Throws<ArgumentNullException>(() => new ChallengeNonceGenerator(null, null));

        [Test]
        public void BuildNonceGeneratorWithoutStoreThrowsArgumentNullException()
        {
            using var rndGenerator = RandomNumberGenerator.Create();
            Assert.Throws<ArgumentNullException>(() =>
                new ChallengeNonceGenerator(rndGenerator, null));
        }

        [Test]
        public void BuildNonceGeneratorWithNegativeTtlThrowsArgumentOutOfRangeException()
        {
            using var rndGenerator = RandomNumberGenerator.Create();
            var generator = new ChallengeNonceGenerator(rndGenerator, this.store);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                generator.GenerateAndStoreNonce(TimeSpan.FromMinutes(1).Negate()));
        }

        [Test]
        public void BuildNonceGeneratorWithZeroTtlThrowsArgumentOutOfRangeException()
        {
            using var rndGenerator = RandomNumberGenerator.Create();
            var generator = new ChallengeNonceGenerator(rndGenerator, this.store);
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                generator.GenerateAndStoreNonce(TimeSpan.Zero));
        }

        [Test]
        public void BuildNonceGeneratorWithRandomNumberGeneratorAndCacheDoesNotThrowException()
        {
            using var rndGenerator = RandomNumberGenerator.Create();
            Assert.DoesNotThrow(() => new ChallengeNonceGenerator(rndGenerator, this.store));
        }

        [Test]
        public void BuildNonceGeneratorWithRandomNumberGeneratorAndCacheAndPositiveTtlDoesNotThrowException()
        {
            using var rndGenerator = RandomNumberGenerator.Create();
            var generator = new ChallengeNonceGenerator(rndGenerator, this.store);
            Assert.DoesNotThrow(() => generator.GenerateAndStoreNonce(TimeSpan.FromMinutes(1)));
        }
    }
}

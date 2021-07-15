namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using Cache;
    using NUnit.Framework;
    using Security.Cache;

    public abstract class AbstractTestWithCache
    {
        private const string CorrectTestNonceKey = "12345678123456781234567812345678";
        private const string IncorrectTestNonceKey = CorrectTestNonceKey + "incorrect";
        private const string TooShortTestNonceKey = "1234567812345678123456781234567";

        protected ICache<DateTime> Cache { get; private set; }

        [SetUp]
        protected virtual void SetUp()
        {
            this.Cache = new MemoryCache<DateTime>();
        }

        public void PutCorrectNonceToCache()
        {
            this.Cache.Put(CorrectTestNonceKey, FiveMinutesFromNow);
        }

        public void PutExpiredNonceToCache()
        {
            this.Cache.Put(CorrectTestNonceKey, DateTime.UtcNow.AddMinutes(-5));
        }

        public void PutIncorrectNonceToCache()
        {
            this.Cache.Put(IncorrectTestNonceKey, FiveMinutesFromNow);
        }

        public void PutTooShortNonceToCache()
        {
            this.Cache.Put(TooShortTestNonceKey, FiveMinutesFromNow);
        }

        [TearDown]
        protected virtual void TearDown()
        {
            this.Cache?.Dispose();
        }

        private static DateTime FiveMinutesFromNow => DateTime.UtcNow.AddMinutes(5);
    }
}

namespace WebEid.Security.Tests.Cache
{
    using System;
    using System.Threading;
    using NUnit.Framework;
    using Security.Cache;

    [TestFixture]
    public class MemoryCacheTests
    {
        /// <summary>
        /// 1. Cache the value
        /// 2. Obtain and remove the value from the cache and make sure it is correct
        /// 3. Make sure the value is removed from the cache
        /// </summary>
        [Test]
        public void CacheItemIsAddedAndRemoved()
        {
            var cacheKey = "CACHE_KEY";
            var cacheValue = "CACHE_VALUE";
            using (ICache<string> cache = new MemoryCache<string>())
            {
                cache.Put(cacheKey, cacheValue);
                Assert.AreEqual(cacheValue, cache.GetAndRemove(cacheKey));
                Assert.IsNull(cache.GetAndRemove(cacheKey));
            }
        }

        /// <summary>
        /// 1. Cache the value
        /// 2. Wait for the value to expire
        /// 3. Make sure the value has expired
        /// </summary>
        [Test]
        public void CacheItemIsExpired()
        {
            var cacheKey = "CACHE_KEY";
            var cacheValue = "CACHE_VALUE";
            using (ICache<string> cache = new MemoryCache<string>(TimeSpan.FromMilliseconds(10)))
            {
                cache.Put(cacheKey, cacheValue);
                Thread.Sleep(10);
                Assert.IsNull(cache.GetAndRemove(cacheKey));
            }
        }
    }
}

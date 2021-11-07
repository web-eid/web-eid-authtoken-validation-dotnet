namespace WebEid.Security.Tests.Cache
{
    using System;
    using Security.Cache;
    using System.Runtime.Caching;

    internal sealed class MemoryCache<T> : ICache<T>
    {
        private readonly MemoryCache cacheContent = new MemoryCache("test-cache");
        private readonly CacheItemPolicy cacheItemPolicy;

        public MemoryCache() : this(ObjectCache.NoSlidingExpiration) { }

        public MemoryCache(TimeSpan cacheItemExpiration)
        {
            this.cacheItemPolicy = new CacheItemPolicy { SlidingExpiration = cacheItemExpiration };
        }

        public T GetAndRemove(string key)
        {
            return this.cacheContent.Contains(key) ? (T)this.cacheContent.Remove(key) : default;
        }

        public bool Contains(string key)
        {
            return this.cacheContent.Contains(key);
        }

        public void Put(string key, T value) => this.cacheContent.Add(key, value, this.cacheItemPolicy);

        public void Dispose() => this.cacheContent?.Dispose();

    }
}

namespace WebEID.Security.Tests.Cache
{
    using System;
    using Security.Cache;
    using System.Runtime.Caching;

    internal sealed class MemoryCache<T> : ICache<T>
    {
        private readonly MemoryCache cacheContent = new MemoryCache("test-cache");
        private readonly CacheItemPolicy cacheItemPolicy;

        public MemoryCache() : this(DateTimeOffset.MaxValue) { }

        public MemoryCache(TimeSpan cacheItemExpiration) : this(DateTimeOffset.Now.Add(cacheItemExpiration)) { }

        public MemoryCache(DateTimeOffset cacheItemExpiration)
        {
            this.cacheItemPolicy = new CacheItemPolicy { AbsoluteExpiration = cacheItemExpiration };
        }

        public T GetAndRemove(string key)
        {
            var value = this.cacheContent.Get(key);
            this.cacheContent.Remove(key);
            return (T)value;
        }

        public bool Contains(string key)
        {
            return this.cacheContent.Contains(key);
        }

        public void Put(string key, T value) => this.cacheContent.Add(key, value, this.cacheItemPolicy);

        public void Dispose() => this.cacheContent?.Dispose();
    }
}

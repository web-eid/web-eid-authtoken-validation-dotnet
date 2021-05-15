namespace WebEID.Security.Cache
{
    using System;

    public interface ICache<T> : IDisposable
    {
        T GetAndRemove(string key);
        void Put(string key, T value);
    }
}

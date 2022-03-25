namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Base class for all authentication token validation exceptions.
    /// </summary>
    [Serializable]
    public abstract class AuthTokenException : Exception
    {
        protected AuthTokenException(string msg) : base(msg)
        {
        }

        protected AuthTokenException(string msg, Exception innerException) : base(msg, innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected AuthTokenException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

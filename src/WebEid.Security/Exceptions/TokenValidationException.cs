namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Base class for all authentication token validation exceptions.
    /// </summary>
    [Serializable]
    public abstract class TokenValidationException : Exception
    {
        protected TokenValidationException(string msg) : base(msg)
        {
        }

        protected TokenValidationException(string msg, Exception innerException) : base(msg, innerException)
        {
        }

        protected TokenValidationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

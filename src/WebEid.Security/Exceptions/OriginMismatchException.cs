namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the origin URL from the token <code>aud</code> field does not match the configured origin,
    /// i.e.the URL that the site is running on.
    /// </summary>
    [Serializable]
    public class OriginMismatchException : TokenValidationException
    {
        public OriginMismatchException() : this(null)
        {
        }

        public OriginMismatchException(Exception innerException) : base("Origin from the token does not match the configured origin", innerException)
        {
        }

        protected OriginMismatchException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the OCSP certificate validation fails.
    /// </summary>
    [Serializable]
    public class OcspCertificateException : TokenValidationException
    {
        public OcspCertificateException(string message) : base(message)
        {
        }

        public OcspCertificateException(string message, Exception innerException) : base(message, innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected OcspCertificateException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

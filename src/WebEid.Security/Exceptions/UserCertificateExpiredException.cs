namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate valid until date is in the past.
    /// </summary>
    [Serializable]
    public class CertificateExpiredException : TokenValidationException
    {
        public CertificateExpiredException(string subject, Exception innerException) : base($"{subject} certificate has expired", innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected CertificateExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

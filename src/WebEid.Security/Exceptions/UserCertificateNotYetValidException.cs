namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate valid from date is in the future.
    /// </summary>
    [Serializable]
    public class CertificateNotYetValidException : TokenValidationException
    {
        public CertificateNotYetValidException(string subject, Exception innerException) : base($"{subject} certificate is not yet valid", innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected CertificateNotYetValidException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

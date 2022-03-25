namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Thrown when the given certificate is not signed by a trusted CA.
    /// </summary>
    [Serializable]
    public class CertificateNotTrustedException : AuthTokenException
    {
        public CertificateNotTrustedException(X509Certificate2 certificate) :
            base($"Certificate {certificate.Subject} is not trusted")
        {
        }

        public CertificateNotTrustedException(X509Certificate2 certificate, string message) :
            base($"Certificate {certificate.Subject} is not trusted: {message}")
        {
        }

        public CertificateNotTrustedException(X509Certificate2 certificate, Exception innerException) :
            base($"Certificate {certificate.Subject} is not trusted", innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected CertificateNotTrustedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

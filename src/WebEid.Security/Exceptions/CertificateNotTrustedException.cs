// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Represents an exception thrown when the given certificate is not signed by a trusted certificate authority (CA) in the Web eID system.
    /// </summary>
    [Serializable]
    public class CertificateNotTrustedException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateNotTrustedException"/> class.
        /// </summary>
        /// <param name="certificate">The certificate that is not trusted.</param>
        public CertificateNotTrustedException(X509Certificate2 certificate) :
            base($"Certificate {certificate.Subject} is not trusted")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateNotTrustedException"/> class with a custom error message.
        /// </summary>
        /// <param name="certificate">The certificate that is not trusted.</param>
        /// <param name="message">The custom error message.</param>
        public CertificateNotTrustedException(X509Certificate2 certificate, string message) :
            base($"Certificate {certificate.Subject} is not trusted: {message}")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateNotTrustedException"/> class with the specified inner exception.
        /// </summary>
        /// <param name="certificate">The certificate that is not trusted.</param>
        /// <param name="innerException">The inner exception.</param>
        public CertificateNotTrustedException(X509Certificate2 certificate, Exception innerException) :
            base($"Certificate {certificate.Subject} is not trusted", innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateNotTrustedException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected CertificateNotTrustedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

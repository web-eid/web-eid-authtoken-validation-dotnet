// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when the user certificate valid from date is in the future in the Web eID system.
    /// </summary>
    [Serializable]
    public class CertificateNotYetValidException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateNotYetValidException"/> class.
        /// </summary>
        /// <param name="subject">The subject of the certificate that is not yet valid.</param>
        /// <param name="innerException">The inner exception.</param>
        public CertificateNotYetValidException(string subject, Exception innerException) : base($"{subject} certificate is not yet valid", innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateNotYetValidException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected CertificateNotYetValidException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

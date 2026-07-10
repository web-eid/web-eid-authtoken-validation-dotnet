// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when the user certificate valid until date is in the past in the Web eID system.
    /// </summary>
    [Serializable]
    public class CertificateExpiredException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateExpiredException"/> class.
        /// </summary>
        /// <param name="subject">The subject of the expired certificate.</param>
        /// <param name="innerException">The inner exception.</param>
        public CertificateExpiredException(string subject, Exception innerException) : base($"{subject} certificate has expired", innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateExpiredException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected CertificateExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

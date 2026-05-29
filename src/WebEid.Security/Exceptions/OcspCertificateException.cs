// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the OCSP certificate validation fails.
    /// </summary>
    [Serializable]
    public class OcspCertificateException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OcspCertificateException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        public OcspCertificateException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OcspCertificateException"/> class with a specified error message and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public OcspCertificateException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OcspCertificateException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected OcspCertificateException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

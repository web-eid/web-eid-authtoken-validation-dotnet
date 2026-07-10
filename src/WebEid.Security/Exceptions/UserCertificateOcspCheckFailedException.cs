// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when the user certificate revocation check with OCSP fails in the Web eID system.
    /// </summary>
    [Serializable]
    public class UserCertificateOcspCheckFailedException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateOcspCheckFailedException"/> class with the specified inner exception.
        /// </summary>
        /// <param name="innerException">The inner exception.</param>
        public UserCertificateOcspCheckFailedException(Exception innerException) : base(
            "User certificate revocation check has failed",
            innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateOcspCheckFailedException"/> class with a custom error message.
        /// </summary>
        /// <param name="message">The custom error message.</param>
        public UserCertificateOcspCheckFailedException(string message) : base(
            $"User certificate revocation check has failed: {message}")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateOcspCheckFailedException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected UserCertificateOcspCheckFailedException(SerializationInfo info, StreamingContext context) :
            base(info, context)
        {
        }
    }
}

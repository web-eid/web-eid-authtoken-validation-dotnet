// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate purpose field is missing or empty.
    /// </summary>
    [Serializable]
    public class UserCertificateMissingPurposeException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateMissingPurposeException"/> class.
        /// </summary>
        public UserCertificateMissingPurposeException() : this(null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateMissingPurposeException"/> class with an inner exception.
        /// </summary>
        /// <param name="innerException">The inner exception.</param>
        public UserCertificateMissingPurposeException(Exception innerException) : base("User certificate purpose is missing", innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateMissingPurposeException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected UserCertificateMissingPurposeException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

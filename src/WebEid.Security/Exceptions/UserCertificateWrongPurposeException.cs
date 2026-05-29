// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when the user certificate purpose is not intended for client authentication in the Web eID system.
    /// </summary>
    [Serializable]
    public class UserCertificateWrongPurposeException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateWrongPurposeException"/> class.
        /// </summary>
        public UserCertificateWrongPurposeException() : base("User certificate is not meant to be used as an authentication certificate")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateWrongPurposeException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected UserCertificateWrongPurposeException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

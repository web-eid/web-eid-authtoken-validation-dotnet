// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when the user certificate has been revoked in the Web eID system.
    /// </summary>
    [Serializable]
    public class UserCertificateRevokedException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateRevokedException"/> class.
        /// </summary>
        public UserCertificateRevokedException() : base("User certificate has been revoked")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateRevokedException"/> class with a custom error message.
        /// </summary>
        /// <param name="message">The custom error message.</param>
        public UserCertificateRevokedException(string message) : base($"User certificate has been revoked: {message}")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateRevokedException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected UserCertificateRevokedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when user certificate parsing fails in the Web eID system.
    /// </summary>
    [Serializable]
    public class UserCertificateParseException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateParseException"/> class with the specified inner exception.
        /// </summary>
        /// <param name="innerException">The inner exception.</param>
        public UserCertificateParseException(Exception innerException) : base("Error parsing certificate", innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateParseException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected UserCertificateParseException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

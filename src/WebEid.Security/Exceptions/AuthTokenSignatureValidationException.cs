// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when authentication token signature validation fails in the Web eID system.
    /// </summary>
    [Serializable]
    public class AuthTokenSignatureValidationException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenSignatureValidationException"/> class.
        /// </summary>
        public AuthTokenSignatureValidationException() : base(ErrorMessage)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenSignatureValidationException"/> class with the specified inner exception.
        /// </summary>
        /// <param name="innerException">The inner exception.</param>
        public AuthTokenSignatureValidationException(Exception innerException) : base(ErrorMessage, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenSignatureValidationException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected AuthTokenSignatureValidationException(SerializationInfo info, StreamingContext context) : base(info, context) { }

        /// <summary>
        /// The error message indicating that token signature validation has failed.
        /// </summary>
        public const string ErrorMessage = "Token signature validation has failed";
    }
}

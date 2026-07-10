// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Base class for all authentication token validation exceptions in the Web eID system.
    /// </summary>
    [Serializable]
    public abstract class AuthTokenException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenException"/> class with the specified error message.
        /// </summary>
        /// <param name="msg">The error message.</param>
        protected AuthTokenException(string msg) : base(msg)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenException"/> class with the specified error message and inner exception.
        /// </summary>
        /// <param name="msg">The error message.</param>
        /// <param name="innerException">The inner exception.</param>
        protected AuthTokenException(string msg, Exception innerException) : base(msg, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected AuthTokenException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when the nonce has expired in the Web eID system.
    /// </summary>
    [Serializable]
    public class ChallengeNonceExpiredException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ChallengeNonceExpiredException"/> class.
        /// </summary>
        public ChallengeNonceExpiredException() : base("Nonce has expired")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ChallengeNonceExpiredException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected ChallengeNonceExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

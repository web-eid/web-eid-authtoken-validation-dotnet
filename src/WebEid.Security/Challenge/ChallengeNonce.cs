// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Challenge
{
    using System;

    /// <summary>
    /// Represents a challenge nonce used in the Web eID system.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="ChallengeNonce"/> class.
    /// </remarks>
    /// <param name="base64EncodedNonce">The base64-encoded value of the nonce.</param>
    /// <param name="expirationTime">The expiration time for the nonce.</param>
    /// <exception cref="ArgumentNullException">Thrown when the provided base64EncodedNonce is null.</exception>
    public class ChallengeNonce(string base64EncodedNonce, DateTime expirationTime)
    {
        /// <summary>
        /// The base64-encoded value of the nonce.
        /// </summary>
        public string Base64EncodedNonce { get; private set; } = base64EncodedNonce ?? throw new ArgumentNullException(nameof(base64EncodedNonce));

        /// <summary>
        /// The expiration time for the nonce.
        /// </summary>
        public DateTime ExpirationTime { get; private set; } = expirationTime;
    }
}

/*
 * Copyright © 2020-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
namespace WebEid.Security.Challenge
{
    using System;

    /// <summary>
    /// Represents a challenge nonce used in the Web eID system.
    /// </summary>
    public class ChallengeNonce
    {
        /// <summary>
        /// The base64-encoded value of the nonce.
        /// </summary>
        public string Base64EncodedNonce { get; private set; }

        /// <summary>
        /// The expiration time for the nonce.
        /// </summary>
        public DateTime ExpirationTime { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ChallengeNonce"/> class.
        /// </summary>
        /// <param name="base64EncodedNonce">The base64-encoded value of the nonce.</param>
        /// <param name="expirationTime">The expiration time for the nonce.</param>
        /// <exception cref="ArgumentNullException">Thrown when the provided base64EncodedNonce is null.</exception>
        public ChallengeNonce(string base64EncodedNonce, DateTime expirationTime)
        {
            this.Base64EncodedNonce = base64EncodedNonce ?? throw new ArgumentNullException(nameof(base64EncodedNonce));
            this.ExpirationTime = expirationTime;
        }
    }
}

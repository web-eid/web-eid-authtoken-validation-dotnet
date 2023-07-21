/*
 * Copyright © 2020-2023 Estonian Information System Authority
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
    using WebEid.Security.Exceptions;

    /// <summary>
    /// Interface representing a store for storing generated challenge nonces and accessing their generation time.
    /// </summary>
    public interface IChallengeNonceStore
    {
        /// <summary>
        /// Inserts given <see cref="ChallengeNonce"/> object into the store.
        /// </summary>
        /// <param name="challengeNonce">The nonce object to be stored.</param>
        void Put(ChallengeNonce challengeNonce);

        [Obsolete]
        ChallengeNonce GetAndRemoveImpl();

        /// <summary>
        /// Removes and returns the <see cref="ChallengeNonce"/> object being stored.
        /// </summary>
        /// <returns>Stored <see cref="ChallengeNonce"/> object.</returns>
        /// <exception cref="ChallengeNonceNotFoundException">Thrown if the stored is empty.</exception>
        /// <exception cref="ChallengeNonceExpiredException">Thrown if the stored <see cref="ChallengeNonce"/> object has been expired.</exception>
        /// <remarks>
        /// The method checks if there is any <see cref="ChallengeNonce"/> stored, and if so then it also check if it is not expired before returning it.
        /// If the Challenge Nonce has been expired then <see cref="ChallengeNonceExpiredException"/> exception is thrown and it is removed from the store.
        /// If there is no Challenge Nonce stored, either no <see cref="Put(ChallengeNonce)"/> method was not called or it was removed previously
        /// due expiration then ChallengeNonceNotFoundException exception is thrown.
        /// </remarks>
        ChallengeNonce GetAndRemove();
    }
}

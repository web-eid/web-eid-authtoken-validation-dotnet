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
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Represents an exception thrown when the user certificate revocation check with OCSP fails in the Web eID system.
    /// </summary>
    [Serializable]
    public class UserCertificateOcspCheckFailedException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateOcspCheckFailedException"/> class with the specified inner exception.
        /// </summary>
        /// <param name="innerException">The inner exception.</param>
        public UserCertificateOcspCheckFailedException(Exception innerException) : base(
            "User certificate revocation check has failed",
            innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateOcspCheckFailedException"/> class with a custom error message.
        /// </summary>
        /// <param name="message">The custom error message.</param>
        public UserCertificateOcspCheckFailedException(string message) : base(
            $"User certificate revocation check has failed: {message}")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateOcspCheckFailedException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected UserCertificateOcspCheckFailedException(SerializationInfo info, StreamingContext context) :
            base(info, context)
        {
        }
    }
}

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when any of the configured disallowed policies is present in the user certificate.
    /// </summary>
    [Serializable]
    public class UserCertificateDisallowedPolicyException : AuthTokenException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateDisallowedPolicyException"/> class.
        /// </summary>
        public UserCertificateDisallowedPolicyException() : base("Disallowed user certificate policy")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserCertificateDisallowedPolicyException"/> class from serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        [ExcludeFromCodeCoverage]
        protected UserCertificateDisallowedPolicyException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

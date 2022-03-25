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
        public UserCertificateDisallowedPolicyException() : base("Disallowed user certificate policy")
        {
        }

        [ExcludeFromCodeCoverage]
        protected UserCertificateDisallowedPolicyException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

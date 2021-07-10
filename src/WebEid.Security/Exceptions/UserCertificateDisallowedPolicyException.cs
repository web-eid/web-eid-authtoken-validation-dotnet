namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when any of the configured disallowed policies is present in the user certificate.
    /// </summary>
    [Serializable]
    public class UserCertificateDisallowedPolicyException : TokenValidationException
    {
        public UserCertificateDisallowedPolicyException() : base("Disallowed user certificate policy")
        {
        }
        protected UserCertificateDisallowedPolicyException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

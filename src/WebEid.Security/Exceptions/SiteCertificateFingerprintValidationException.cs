namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the site HTTPS certificate fingerprint from the token <code>aud</code> field does not match
    /// the configured site certificate fingerprint that the site is using.
    /// </summary>
    [Serializable]
    public class SiteCertificateFingerprintValidationException : TokenValidationException
    {
        public SiteCertificateFingerprintValidationException() : base("Server certificate fingerprint does not match the configured fingerprint")
        {
        }

        [ExcludeFromCodeCoverage]
        protected SiteCertificateFingerprintValidationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}

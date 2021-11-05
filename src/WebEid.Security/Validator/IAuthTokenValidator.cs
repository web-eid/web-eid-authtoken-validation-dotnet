namespace WebEid.Security.Validator
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Util;

    public interface IAuthTokenValidator
    {
        /// <summary>
        /// Validates the Web eID OpenID X509 ID Token authentication token signed by the subject and returns
        /// the subject certificate that can be used for retrieving information about the subject.
        /// </summary>
        /// <param name="authTokenWithSignature">the Web eID authentication token, in OpenID X509 ID Token format, with signature</param>
        /// <returns>validated subject certificate</returns>
        /// <exception cref="TokenValidationException">When validation fails</exception>
        [Obsolete("Use validate(string, string) instead.")]
        Task<X509Certificate> Validate(string authTokenWithSignature);

        /// <summary>
        /// Validates the Web eID authentication token signed by the subject and returns
        /// the subject certificate that can be used for retrieving information about the subject.
        /// See <see cref="X509CertificateExtensions"/> for convenience methods for retrieving user
        /// information from the certificate.
        /// </summary>
        /// <param name="authToken">the Web eID authentication token, in Web eID custom format</param>
        /// <param name="currentNonce"></param>
        /// <returns>validated subject certificate</returns>
        /// <exception cref="TokenValidationException">When validation fails</exception>
        Task<X509Certificate> Validate(string authToken, string currentNonce);
    }
}

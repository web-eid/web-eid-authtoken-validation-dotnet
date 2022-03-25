namespace WebEid.Security.Validator
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Util;
    using WebEid.Security.AuthToken;

    public interface IAuthTokenValidator
    {
        const string CURRENT_TOKEN_FORMAT_VERSION = "web-eid:1";

        /// <summary>
        /// Parses the Web eID authentication token signed by the subject.
        /// </summary>
        /// <param name="authToken">the Web eID authentication token string, in Web eID JSON format</param>
        /// <returns>the Web eID authentication token</returns>
        /// <exception cref="AuthTokenException">When parsing fails</exception>
        WebEidAuthToken Parse(string authToken);

        /// <summary>
        /// Validates the Web eID authentication token signed by the subject and returns
        /// the subject certificate that can be used for retrieving information about the subject.
        /// See <see cref="X509CertificateExtensions"/> for convenience methods for retrieving user
        /// information from the certificate.
        /// </summary>
        /// <param name="authToken">the Web eID authentication token, in Web eID custom format</param>
        /// <param name="currentChallengeNonce"></param>
        /// <returns>validated subject certificate</returns>
        /// <exception cref="AuthTokenException">When validation fails</exception>
        Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce);
    }
}

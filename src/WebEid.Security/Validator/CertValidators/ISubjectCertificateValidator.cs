namespace WebEid.Security.Validator.CertValidators
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    /// <summary>
    /// Validators perform the actual user certificate validation actions.
    /// They are used by AuthTokenValidator internally and are not part of the public API.
    /// </summary>
    internal interface ISubjectCertificateValidator
    {
        Task Validate(X509Certificate2 subjectCertificate);
    }
}

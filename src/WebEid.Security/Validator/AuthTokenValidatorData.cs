namespace WebEID.Security.Validator
{
    using System.Security.Cryptography.X509Certificates;

    public class AuthTokenValidatorData
    {
        public AuthTokenValidatorData(X509Certificate subjectCertificate)
        {
            this.SubjectCertificate = subjectCertificate;
        }

        public X509Certificate SubjectCertificate { get; }

        public string Nonce { get; set; }

        public string Origin { get; set; }

        public string SiteCertificateFingerprint { get; set; }
    }
}

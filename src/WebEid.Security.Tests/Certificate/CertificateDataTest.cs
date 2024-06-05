namespace WebEid.Security.Tests.Certificate
{
    using System.Security.Cryptography.X509Certificates;
    using NUnit.Framework;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Util;

    public class CertificateTests
    {
        [Test]
        public void WhenOrganizationCertificateThenSubjectCNAndIdCodeAndCountryCodeExtractionSucceeds()
        {
            X509Certificate organizationCert = Certificates.GetOrganizationCert();
            Assert.That(organizationCert.GetSubjectCn(), Is.EqualTo("Testijad.ee isikutuvastus"));
            Assert.That(organizationCert.GetSubjectIdCode(), Is.EqualTo("12276279"));
            Assert.That(organizationCert.GetSubjectCountryCode(), Is.EqualTo("EE"));
        }

        [Test]
        public void WhenOrganizationCertificateThenSubjectGivenNameAndSurnameAreNull()
        {
            X509Certificate organizationCert = Certificates.GetOrganizationCert();
            Assert.That(organizationCert.GetSubjectGivenName(), Is.Null);
            Assert.That(organizationCert.GetSubjectSurname(), Is.Null);
        }
    }
}

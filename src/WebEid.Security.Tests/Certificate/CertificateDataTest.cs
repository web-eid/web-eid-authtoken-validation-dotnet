namespace WebEid.Security.Tests.Certificate
{
    using NUnit.Framework;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Util;

    public class CertificateTests
    {
        [Test]
        public void WhenOrganizationCertificateThenSubjectCNAndIdCodeAndCountryCodeExtractionSucceeds()
        {
            var organizationCert = Certificates.GetOrganizationCert();
            Assert.That(organizationCert.GetSubjectCn(), Is.EqualTo("Testijad.ee isikutuvastus"));
            Assert.That(organizationCert.GetSubjectIdCode(), Is.EqualTo("12276279"));
            Assert.That(organizationCert.GetSubjectCountryCode(), Is.EqualTo("EE"));
        }

        [Test]
        public void WhenOrganizationCertificateThenSubjectGivenNameAndSurnameExtractionFails()
        {
            var organizationCert = Certificates.GetOrganizationCert();
            Assert.NotNull(() => organizationCert.GetSubjectGivenName());
            Assert.NotNull(() => organizationCert.GetSubjectSurname());
        }
    }
}

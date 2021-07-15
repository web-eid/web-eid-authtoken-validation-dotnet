namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Org.BouncyCastle.Security;
    using Security.Validator.Ocsp;
    using Security.Validator.Ocsp.Service;

    public class OcspServiceMaker
    {
        private const string TestOcspAccessLocation = "http://demo.sk.ee/ocsp";
        private static readonly List<X509Certificate2> TrustedCaCertificates;
        private static readonly Uri TestEsteid2015 = new Uri("http://aia.demo.sk.ee/esteid2015");

        static OcspServiceMaker()
        {
            TrustedCaCertificates = new List<X509Certificate2>
            {
                new X509Certificate2(Certificates.GetTestEsteid2015Ca()),
                new X509Certificate2(Certificates.GetTestEsteid2018Ca())
            };
        }

        public static OcspServiceProvider GetAiaOcspServiceProvider()
        {
            return new OcspServiceProvider(null, GetAiaOcspServiceConfiguration());
        }

        public static OcspServiceProvider GetDesignatedOcspServiceProvider()
        {
            return new OcspServiceProvider(GetDesignatedOcspServiceConfiguration(), GetAiaOcspServiceConfiguration());
        }

        public static OcspServiceProvider GetDesignatedOcspServiceProvider(bool doesSupportNonce)
        {
            return new OcspServiceProvider(GetDesignatedOcspServiceConfiguration(doesSupportNonce), GetAiaOcspServiceConfiguration());
        }

        public static OcspServiceProvider GetDesignatedOcspServiceProvider(String ocspServiceAccessLocation)
        {
            return new OcspServiceProvider(GetDesignatedOcspServiceConfiguration(true, ocspServiceAccessLocation), GetAiaOcspServiceConfiguration());
        }

        private static AiaOcspServiceConfiguration GetAiaOcspServiceConfiguration()
        {
            return new AiaOcspServiceConfiguration(new List<Uri> { OcspUrls.AiaEsteid2015, TestEsteid2015 },
                TrustedCaCertificates);
        }

        public static DesignatedOcspServiceConfiguration GetDesignatedOcspServiceConfiguration()
        {
            return GetDesignatedOcspServiceConfiguration(true, TestOcspAccessLocation);
        }

        private static DesignatedOcspServiceConfiguration GetDesignatedOcspServiceConfiguration(bool doesSupportNonce)
        {
            return GetDesignatedOcspServiceConfiguration(doesSupportNonce, TestOcspAccessLocation);
        }

        private static DesignatedOcspServiceConfiguration GetDesignatedOcspServiceConfiguration(bool doesSupportNonce, string ocspServiceAccessLocation)
        {
            return new DesignatedOcspServiceConfiguration(
                new Uri(ocspServiceAccessLocation),
                DotNetUtilities.FromX509Certificate(Certificates.GetTestSkOcspResponder2020()),
                TrustedCaCertificates.Select(c => DotNetUtilities.FromX509Certificate(c)).ToList(),
                doesSupportNonce);
        }
    }
}

namespace WebEID.Security.Tests.TestUtils
{
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    internal static class CertificateLoader
    {
        public static X509Certificate[] LoadCertificatesFromResources(params string[] resourceNames)
        {
            return resourceNames?.Select(resourceName => LoadCertificateFromResource(resourceName)).ToArray() ??
                   Array.Empty<X509Certificate>();
        }

        public static X509Certificate LoadCertificateFromResource(string resourceName)
        {
            return new X509Certificate(ResourceReader.ReadFromResource(resourceName));
        }
    }
}

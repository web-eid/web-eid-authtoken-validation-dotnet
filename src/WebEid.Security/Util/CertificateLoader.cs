namespace WebEid.Security.Util
{
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    public class CertificateLoader
    {
        private readonly ResourceReader resourceReader;

        public CertificateLoader(ResourceReader resourceReader) => this.resourceReader = resourceReader;

        public X509Certificate2[] LoadCertificatesFromResources(params string[] resourceNames) =>
            resourceNames?.Select(resourceName => this.LoadCertificateFromResource(resourceName)).ToArray() ??
                   Array.Empty<X509Certificate2>();

        public X509Certificate2 LoadCertificateFromResource(string resourceName) =>
            new X509Certificate2(this.resourceReader.ReadFromResource(resourceName));

        public static X509Certificate2 LoadCertificateFromBase64String(string certificate) =>
            new X509Certificate2(Convert.FromBase64String(certificate));
    }
}

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Util
{
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Provides functionality for loading X.509 certificates from resources or base64-encoded strings.
    /// </summary>
    public class CertificateLoader
    {
        private readonly ResourceReader resourceReader;

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateLoader"/> class.
        /// </summary>
        /// <param name="resourceReader">The resource reader used to load certificates from resources.</param>
        public CertificateLoader(ResourceReader resourceReader) => this.resourceReader = resourceReader;

        /// <summary>
        /// Loads X.509 certificates from resources.
        /// </summary>
        /// <param name="resourceNames">The names of the resources containing certificates.</param>
        /// <returns>An array of loaded X.509 certificates.</returns>
        public X509Certificate2[] LoadCertificatesFromResources(params string[] resourceNames) =>
            resourceNames?.Select(resourceName => this.LoadCertificateFromResource(resourceName)).ToArray() ??
            Array.Empty<X509Certificate2>();

        /// <summary>
        /// Loads an X.509 certificate from a resource.
        /// </summary>
        /// <param name="resourceName">The name of the resource containing the certificate.</param>
        /// <returns>The loaded X.509 certificate.</returns>
        public X509Certificate2 LoadCertificateFromResource(string resourceName) =>
            new X509Certificate2(this.resourceReader.ReadFromResource(resourceName));

        /// <summary>
        /// Loads an X.509 certificate from a base64-encoded string.
        /// </summary>
        /// <param name="certificate">The base64-encoded certificate string.</param>
        /// <returns>The loaded X.509 certificate.</returns>
        public static X509Certificate2 LoadCertificateFromBase64String(string certificate) =>
            new X509Certificate2(Convert.FromBase64String(certificate));
    }
}

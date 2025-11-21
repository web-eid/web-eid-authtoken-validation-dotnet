// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Util
{
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Provides extension methods for working with <see cref="X509Certificate2"/> instances.
    /// </summary>
    public static class X509Certificate2Extensions
    {
        /// <summary>
        /// Converts a <see cref="X509Certificate2"/> into an equivalent
        /// BouncyCastle <see cref="Org.BouncyCastle.X509.X509Certificate"/> instance.
        /// </summary>
        public static Org.BouncyCastle.X509.X509Certificate ToBouncyCastle(this X509Certificate2 certificate)
        {
            var parser = new Org.BouncyCastle.X509.X509CertificateParser();
            return parser.ReadCertificate(certificate.RawData);
        }
    }
}

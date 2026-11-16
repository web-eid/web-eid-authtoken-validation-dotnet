// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Certificates
{
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    internal static class CertificateLoader
    {
        public static X509Certificate2[] LoadTrustedCaCertificatesFromDisk(bool isTest = false) => [.. new FileReader(GetCertPath(isTest), "*.cer").ReadFiles().Select(X509CertificateLoader.LoadCertificate)];

        private static string GetCertPath(bool isTest) => isTest ? "Certificates/Dev" : "Certificates/Prod";
    }

    internal sealed class FileReader(string path, string? searchPattern = null)
    {
        private readonly string path = path;
        private readonly string? searchPattern = searchPattern;

        public IEnumerable<byte[]> ReadFiles()
        {
            foreach (var file in Directory.EnumerateFiles(path, searchPattern ?? "*"))
            {
                yield return File.ReadAllBytes(file);
            }
        }
    }
}

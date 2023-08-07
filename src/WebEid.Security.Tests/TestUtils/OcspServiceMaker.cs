/*
 * Copyright © 2020-2023 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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
        private static readonly Uri TestEsteid2015 = new("http://aia.demo.sk.ee/esteid2015");

        static OcspServiceMaker() => TrustedCaCertificates = new List<X509Certificate2>
            {
                new X509Certificate2(Certificates.GetTestEsteid2015Ca()),
                new X509Certificate2(Certificates.GetTestEsteid2018Ca())
            };

        public static OcspServiceProvider GetAiaOcspServiceProvider() => new(null, GetAiaOcspServiceConfiguration());

        public static OcspServiceProvider GetDesignatedOcspServiceProvider() => new(GetDesignatedOcspServiceConfiguration(), GetAiaOcspServiceConfiguration());

        public static OcspServiceProvider GetDesignatedOcspServiceProvider(bool doesSupportNonce) => new(GetDesignatedOcspServiceConfiguration(doesSupportNonce), GetAiaOcspServiceConfiguration());

        public static OcspServiceProvider GetDesignatedOcspServiceProvider(string ocspServiceAccessLocation) => new(GetDesignatedOcspServiceConfiguration(true, ocspServiceAccessLocation), GetAiaOcspServiceConfiguration());

        private static AiaOcspServiceConfiguration GetAiaOcspServiceConfiguration() => new(new List<Uri> { OcspUrls.AiaEsteid2015, TestEsteid2015 }, TrustedCaCertificates);

        public static DesignatedOcspServiceConfiguration GetDesignatedOcspServiceConfiguration() => GetDesignatedOcspServiceConfiguration(true, TestOcspAccessLocation);

        private static DesignatedOcspServiceConfiguration GetDesignatedOcspServiceConfiguration(bool doesSupportNonce) => GetDesignatedOcspServiceConfiguration(doesSupportNonce, TestOcspAccessLocation);

        private static DesignatedOcspServiceConfiguration GetDesignatedOcspServiceConfiguration(bool doesSupportNonce, string ocspServiceAccessLocation) => new(
                new Uri(ocspServiceAccessLocation),
                DotNetUtilities.FromX509Certificate(Certificates.GetTestSkOcspResponder2020()),
                TrustedCaCertificates.Select(c => DotNetUtilities.FromX509Certificate(c)).ToList(),
                doesSupportNonce);
    }
}

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
namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.Linq;
    using System.Text;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;

    public static class OcspUrls
    {
        /// <summary>
        /// Returns the OCSP responder <see cref="Uri">Uri</see> or null if it doesn't have one.
        /// </summary>
        /// <param name="certificate">Certificate where the OCSP is parsed.</param>
        /// <returns></returns>
        public static Uri GetOcspUri(this Org.BouncyCastle.X509.X509Certificate certificate)
        {
            var authorityInfoAccess = certificate.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
            if (authorityInfoAccess == null)
            {
                return null;
            }

            try
            {
                var asn = Asn1Sequence.GetInstance(authorityInfoAccess.GetOctets());
                var obj = asn.OfType<DerSequence>()
                    .First(seq => seq.OfType<DerObjectIdentifier>().Any(oid => AccessDescription.IdADOcsp.Equals(oid)));
                var taggedObject = obj.OfType<DerTaggedObject>().First();
                var octetStr = Asn1OctetString.GetInstance(taggedObject.GetObject());
                var uri = Encoding.UTF8.GetString(octetStr.GetOctets());
                return new Uri(uri);
            }
            catch
            {
                return null;
            }
        }
    }
}

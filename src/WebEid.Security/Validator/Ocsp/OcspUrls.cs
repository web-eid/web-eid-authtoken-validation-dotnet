namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.Linq;
    using System.Text;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;

    public static class OcspUrls
    {
#pragma warning disable S1075 // URIs should not be hardcoded
        public static readonly Uri AiaEsteid2015 = new Uri("http://aia.sk.ee/esteid2015"); //NOSONAR
#pragma warning restore S1075 // URIs should not be hardcoded

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

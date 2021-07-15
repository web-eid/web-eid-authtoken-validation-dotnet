namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.Collections;
    using System.Security.Cryptography;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Ocsp;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Ocsp;

    public class OcspRequestBuilder
    {
        private bool ocspNonceEnabled = true;
        private CertificateID certificateId;

        public byte[] Nonce { get; private set; }

        public OcspRequestBuilder WithCertificateId(CertificateID certificateId)
        {
            this.certificateId = certificateId;
            return this;
        }

        public OcspRequestBuilder EnableOcspNonce(bool enable)
        {
            this.ocspNonceEnabled = enable;
            return this;
        }

        /// <summary>
        /// The returned <see cref="OcspReq"/> is not re-usable/cacheable! It contains a one-time nonce
        /// and responders will reject subsequent requests that have the same nonce value.
        /// </summary>
        /// <returns>An instance of OcspReq object</returns>
        public OcspReq Build()
        {
            ValidateParameters(this.certificateId);

            var generator = new OcspReqGenerator();
            generator.AddRequest(this.certificateId);

            if (this.ocspNonceEnabled)
            {
                this.AddNonce(generator);
            }

            return generator.Generate();
        }

        private static void ValidateParameters(CertificateID certificateId)
        {
            if (certificateId == null)
            {
                throw new ArgumentNullException(nameof(certificateId));
            }
        }

        private void AddNonce(OcspReqGenerator builder)
        {
            this.Nonce = new byte[8];

            using (var rndGenerator = RNGCryptoServiceProvider.Create())
            {
                rndGenerator.GetBytes(this.Nonce);
            }

            IDictionary extensions = new Hashtable
            {
                { OcspObjectIdentifiers.PkixOcspNonce, new X509Extension(false, new DerOctetString(this.Nonce)) }
            };
            builder.SetRequestExtensions(new X509Extensions(extensions));
        }
    }
}

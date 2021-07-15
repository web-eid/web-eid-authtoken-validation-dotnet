namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.X509;

    public sealed class DesignatedOcspServiceConfiguration
    {
        public DesignatedOcspServiceConfiguration(Uri ocspServiceAccessLocation,
            X509Certificate responderCertificate,
            List<X509Certificate> supportedCertificateIssuers,
            bool doesSupportNonce = true)
        {
            this.OcspServiceAccessLocation = ocspServiceAccessLocation ??
                                             throw new ArgumentNullException(nameof(ocspServiceAccessLocation));
            this.ResponderCertificate =
                responderCertificate ?? throw new ArgumentNullException(nameof(responderCertificate));
            this.SupportedIssuers = supportedCertificateIssuers.Select(i => i.SubjectDN).ToList();
            this.DoesSupportNonce = doesSupportNonce;
            OcspResponseValidator.ValidateHasSigningExtension(responderCertificate);
        }

        public Uri OcspServiceAccessLocation { get; }
        public X509Certificate ResponderCertificate { get; }
        public List<X509Name> SupportedIssuers { get; }
        public bool DoesSupportNonce { get; }

        public bool SupportsIssuerOf(X509Certificate certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }
            return this.SupportedIssuers.Contains(certificate.IssuerDN);
        }
    }
}

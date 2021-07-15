namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;
    using Exceptions;
    using Org.BouncyCastle.X509;
    using Util;

    /// <summary>
    /// An OCSP service that uses a single designated OCSP responder.
    /// </summary>
    internal class DesignatedOcspService : IOcspService
    {
        private readonly DesignatedOcspServiceConfiguration configuration;

        public DesignatedOcspService(DesignatedOcspServiceConfiguration configuration)
        {
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.DoesSupportNonce = this.configuration.DoesSupportNonce;
        }

        public bool DoesSupportNonce { get; }
        public Uri AccessLocation => this.configuration.OcspServiceAccessLocation;

        public bool SupportsIssuerOf(X509Certificate certificate) => this.configuration.SupportsIssuerOf(certificate);

        public void ValidateResponderCertificate(X509Certificate responderCertificate, DateTime producedAt)
        {
            // Certificate pinning is implemented simply by comparing the certificates or their public keys,
            // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
            if (!this.configuration.ResponderCertificate.Equals(responderCertificate))
            {
                throw new OcspCertificateException(
                    "Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");
            }
            responderCertificate.ValidateCertificateExpiry(producedAt, "Designated OCSP responder");
        }
    }
}

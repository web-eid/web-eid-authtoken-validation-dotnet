namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using Service;

    public class OcspServiceProvider
    {
        private readonly DesignatedOcspService designatedOcspService;
        private readonly AiaOcspServiceConfiguration aiaOcspServiceConfiguration;

        public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration)
        {
            this.designatedOcspService = designatedOcspServiceConfiguration != null ? new DesignatedOcspService(designatedOcspServiceConfiguration) : null;
            this.aiaOcspServiceConfiguration = aiaOcspServiceConfiguration ??
                                               throw new ArgumentNullException(nameof(aiaOcspServiceConfiguration));
        }

        public IOcspService GetService(Org.BouncyCastle.X509.X509Certificate certificate = null)
        {
            if (this.designatedOcspService != null && this.designatedOcspService.SupportsIssuerOf(certificate))
            {
                return this.designatedOcspService;
            }
            return new AiaOcspService(this.aiaOcspServiceConfiguration, certificate);
        }
    }
}

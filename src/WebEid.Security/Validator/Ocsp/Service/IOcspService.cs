namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;

    public interface IOcspService
    {
        bool DoesSupportNonce { get; }
        Uri AccessLocation { get; }
        void ValidateResponderCertificate(Org.BouncyCastle.X509.X509Certificate responderCertificate, DateTime producedAt);
    }
}

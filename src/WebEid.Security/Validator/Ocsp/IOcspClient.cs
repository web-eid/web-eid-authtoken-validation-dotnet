namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.Threading.Tasks;
    using Org.BouncyCastle.Ocsp;

    public interface IOcspClient : IDisposable
    {
        Task<OcspResp> Request(Uri uri, OcspReq ocspReq);
    }
}

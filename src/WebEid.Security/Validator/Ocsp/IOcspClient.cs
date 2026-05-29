// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.Threading.Tasks;
    using Org.BouncyCastle.Ocsp;

    /// <summary>
    /// Interface for making OCSP (Online Certificate Status Protocol) requests.
    /// </summary>
    public interface IOcspClient : IDisposable
    {
        /// <summary>
        /// Sends an OCSP request to the specified URI and retrieves the OCSP response.
        /// </summary>
        /// <param name="uri">The URI of the OCSP responder.</param>
        /// <param name="ocspReq">The OCSP request to be sent.</param>
        /// <returns>The OCSP response.</returns>
        Task<OcspResp> Request(Uri uri, OcspReq ocspReq);
    }
}

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using Org.BouncyCastle.Ocsp;

    internal sealed class OcspClient : IOcspClient
    {
        private readonly HttpClientHandler httpClientHandler;
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        private const string OcspRequestType = "application/ocsp-request";
        private const string OcspResponseType = "application/ocsp-response";


        public OcspClient(TimeSpan ocspRequestTimeout, ILogger logger = null)
        {
            httpClientHandler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.GZip };
            httpClient = new HttpClient(httpClientHandler) { Timeout = ocspRequestTimeout };
            this.logger = logger;
        }

        /// <summary>
        /// Fetch the OCSP response from the CA's OCSP responder server.
        /// </summary>
        /// <param name="uri">OCSP server URL</param>
        /// <param name="ocspReq">OCSP request</param>
        /// <returns>OCSP response from the server</returns>
        /// <exception cref="IOException">if response has wrong content type.</exception>
        public async Task<OcspResp> Request(Uri uri, OcspReq ocspReq)
        {
            var data = ocspReq.GetEncoded();
            var content = new ByteArrayContent(data);
            content.Headers.ContentType = new MediaTypeHeaderValue(OcspRequestType);
            content.Headers.ContentLength = data.Length;
            var response = await httpClient.PostAsync(uri, content);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"OCSP request was not successful, response: {response}");
            }

            if (logger?.IsEnabled(LogLevel.Debug) == true)
            {
                logger.LogDebug("OCSP response: {Response}", response);
            }

            if (response.Content.Headers.ContentType != null &&
                response.Content.Headers.ContentType.MediaType != OcspResponseType)
            {
                throw new IOException($"OCSP response content type is not {OcspResponseType}");
            }

            var resp = await response.Content.ReadAsByteArrayAsync();
            return new OcspResp(resp);
        }

        public void Dispose()
        {
            httpClient?.Dispose();
            httpClientHandler?.Dispose();
        }
    }
}

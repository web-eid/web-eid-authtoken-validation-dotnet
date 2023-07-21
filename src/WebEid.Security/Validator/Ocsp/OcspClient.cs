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
            this.httpClientHandler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.GZip };
            this.httpClient = new HttpClient(this.httpClientHandler) { Timeout = ocspRequestTimeout };
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
            var response = await this.httpClient.PostAsync(uri, content);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"OCSP request was not successful, response: {response}");
            }
            this.logger?.LogDebug("OCSP response: {0}", response);

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
            this.httpClient?.Dispose();
            this.httpClientHandler?.Dispose();
        }
    }
}

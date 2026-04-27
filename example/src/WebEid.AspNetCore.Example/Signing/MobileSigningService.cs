// Copyright (c) 2025-2025 Estonian Information System Authority
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

namespace WebEid.AspNetCore.Example.Signing
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using Dto;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.WebUtilities;
    using Services;

    public class MobileSigningService(
        SigningService signingService,
        IHttpContextAccessor httpContextAccessor,
        MobileRequestUriBuilder uriBuilder
    )
    {
        private const string WebEidMobileSignPath = "sign";
        private const string WebEidMobileCertPath = "cert";
        private const string CertificateResponsePath = "/sign/mobile/certificate";
        private const string SignatureResponsePath = "/sign/mobile/signature";

        public MobileInitRequest InitCertificateOrSigningRequest(ClaimsIdentity identity, string containerName)
        {
            var signingCert = identity.FindFirst("signingCertificate")?.Value;
            var algosJson = identity.FindFirst("supportedSignatureAlgorithms")?.Value;

            if (string.IsNullOrEmpty(signingCert) || string.IsNullOrEmpty(algosJson))
            {
                return InitCertificateRequest();
            }

            var algorithms =
                JsonSerializer.Deserialize<List<SignatureAlgorithmDto>>(algosJson)
                ?? [];

            var certDto = new CertificateDto
            {
                CertificateBase64String = signingCert,
                SupportedSignatureAlgorithms = algorithms
            };

            return InitSigningRequest(identity, certDto, containerName);
        }

        private MobileInitRequest InitCertificateRequest()
        {
            var request = httpContextAccessor.HttpContext!.Request;
            var baseUrl = $"{request.Scheme}://{request.Host}";
            var responseUri = $"{baseUrl}{CertificateResponsePath}";

            var requestObj = new RequestObject
            {
                ResponseUri = responseUri
            };

            var encoded = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(requestObj)));
            var requestUri = uriBuilder.Build(WebEidMobileCertPath, encoded);

            return new MobileInitRequest
            {
                RequestUri = requestUri
            };
        }

        public MobileInitRequest InitSigningRequest(
            ClaimsIdentity identity,
            CertificateDto certificateDto,
            string containerName)
        {
            var digest = signingService.PrepareContainer(certificateDto, identity, containerName);
            var request = httpContextAccessor.HttpContext!.Request;
            var baseUrl = $"{request.Scheme}://{request.Host}";
            var responseUri = $"{baseUrl}{SignatureResponsePath}";

            var requestObj = new RequestObject
            {
                ResponseUri = responseUri,
                SigningCertificate = certificateDto.CertificateBase64String,
                Hash = digest.Hash,
                HashFunction = digest.HashFunction
            };

            var encoded = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(requestObj)));
            var requestUri = uriBuilder.Build(WebEidMobileSignPath, encoded);

            return new MobileInitRequest
            {
                RequestUri = requestUri
            };
        }

        public sealed record MobileInitRequest
        {
            [JsonInclude]
            [JsonPropertyName("requestUri")]
            public required string RequestUri { get; init; }
        }

        internal sealed record RequestObject
        {
            [JsonInclude]
            [JsonPropertyName("responseUri")]
            public required string ResponseUri { get; init; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            [JsonPropertyName("signingCertificate")]
            public string? SigningCertificate { get; init; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            [JsonPropertyName("hash")]
            public string? Hash { get; init; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            [JsonPropertyName("hashFunction")]
            public string? HashFunction { get; init; }
        }
    }
}

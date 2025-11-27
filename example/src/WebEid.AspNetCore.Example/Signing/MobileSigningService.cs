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
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using Microsoft.Extensions.Options;
    using Microsoft.AspNetCore.Http;
    using Dto;
    using Options;
    using Services;

    public class MobileSigningService(
        SigningService signingService,
        IOptions<WebEidMobileOptions> mobileOptions,
        IHttpContextAccessor httpContextAccessor
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

            var encoded = Base64UrlEncode(JsonSerializer.Serialize(requestObj));
            var requestUri = BuildMobileRequestUri(WebEidMobileCertPath, encoded);

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

            var encoded = Base64UrlEncode(JsonSerializer.Serialize(requestObj));
            var requestUri = BuildMobileRequestUri(WebEidMobileSignPath, encoded);

            return new MobileInitRequest
            {
                RequestUri = requestUri
            };
        }

        private static string Base64UrlEncode(string input)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(input))
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }

        private string BuildMobileRequestUri(string path, string encoded)
        {
            var baseUri = mobileOptions.Value.BaseRequestUri;
            return baseUri.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? $"{baseUri.TrimEnd('/')}/{path}#{encoded}"
                : $"{baseUri}{path}#{encoded}";
        }

        public sealed record MobileInitRequest
        {
            [JsonInclude]
            [JsonPropertyName("request_uri")]
            public required string RequestUri { get; init; }
        }

        internal sealed record RequestObject
        {
            [JsonInclude]
            [JsonPropertyName("response_uri")]
            public required string ResponseUri { get; init; }

            [JsonInclude]
            [JsonPropertyName("signing_certificate")]
            public string SigningCertificate { get; init; } = null!;

            [JsonInclude]
            [JsonPropertyName("hash")]
            public string Hash { get; init; } = null!;

            [JsonInclude]
            [JsonPropertyName("hash_function")]
            public string HashFunction { get; init; } = null!;
        }
    }
}
// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
    using Microsoft.Extensions.Configuration;
    using Services;

    public class MobileSigningService(
        SigningService signingService,
        IHttpContextAccessor httpContextAccessor,
        MobileRequestUriBuilder uriBuilder,
        IConfiguration configuration
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
            var responseUri = $"{configuration["OriginUrl"]}{CertificateResponsePath}";
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
            var responseUri = $"{configuration["OriginUrl"]}{SignatureResponsePath}";

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

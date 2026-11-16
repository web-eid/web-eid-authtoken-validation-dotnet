// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.Options;
    using Options;
    using Security.Challenge;
    using Services;

    [ApiController]
    [Route("auth/mobile")]
    public class MobileAuthInitController(
        IChallengeNonceGenerator nonceGenerator,
        IOptions<WebEidMobileOptions> mobileOptions,
        MobileRequestUriBuilder uriBuilder,
        IConfiguration configuration
    ) : ControllerBase
    {
        private const string WebEidMobileAuthPath = "auth";
        private const string MobileLoginPath = "/auth/mobile/login";

        [HttpPost("init")]
        public IActionResult Init()
        {
            var challenge = nonceGenerator.GenerateAndStoreNonce(TimeSpan.FromMinutes(5));
            var challengeBase64 = challenge.Base64EncodedNonce;

            var loginUri = $"{configuration["OriginUrl"]}{MobileLoginPath}";

            var payload = new AuthPayload
            {
                Challenge = challengeBase64,
                LoginUri = loginUri,
                GetSigningCertificate = mobileOptions.Value.RequestSigningCert ? true : null
            };

            var json = JsonSerializer.Serialize(payload);
            var encodedPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

            var authUri = uriBuilder.Build(WebEidMobileAuthPath, encodedPayload);

            return Ok(new AuthUri
            {
                AuthUriValue = authUri
            });
        }

        private sealed record AuthPayload
        {
            [JsonInclude]
            [JsonPropertyName("challenge")]
            public required string Challenge { get; init; }

            [JsonInclude]
            [JsonPropertyName("loginUri")]
            public required string LoginUri { get; init; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            [JsonPropertyName("getSigningCertificate")]
            public bool? GetSigningCertificate { get; init; }
        }

        private sealed record AuthUri
        {
            [JsonInclude]
            [JsonPropertyName("authUri")]
            public required string AuthUriValue { get; init; }
        }
    }
}

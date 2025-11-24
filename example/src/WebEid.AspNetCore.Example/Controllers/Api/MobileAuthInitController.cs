// Copyright (c) 2021-2024 Estonian Information System Authority
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

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using System.Text;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Options;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using Options;
    using Security.Challenge;

    [ApiController]
    [Route("auth/mobile")]
    public class MobileAuthInitController(
        IChallengeNonceGenerator nonceGenerator,
        IOptions<WebEidMobileOptions> mobileOptions
    ) : ControllerBase
    {
        private const string WebEidMobileAuthPath = "auth";
        private const string MobileLoginPath = "/auth/mobile/login";

        [HttpPost("init")]
        public IActionResult Init()
        {
            var challenge = nonceGenerator.GenerateAndStoreNonce(TimeSpan.FromMinutes(5));
            var challengeBase64 = challenge.Base64EncodedNonce;

            var loginUri = $"{Request.Scheme}://{Request.Host}{MobileLoginPath}";

            var payload = new AuthPayload
            {
                Challenge = challengeBase64,
                LoginUri = loginUri,
                GetSigningCertificate = mobileOptions.Value.RequestSigningCert ? true : null
            };

            var json = JsonSerializer.Serialize(payload);
            var encodedPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

            var authUri = BuildAuthUri(encodedPayload);

            return Ok(new AuthUri
            {
                AuthUriValue = authUri
            });
        }

        private string BuildAuthUri(string encodedPayload)
        {
            var baseUri = mobileOptions.Value.BaseRequestUri;

            return baseUri.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? $"{baseUri.TrimEnd('/')}/{WebEidMobileAuthPath}#{encodedPayload}"
                : $"{baseUri}{WebEidMobileAuthPath}#{encodedPayload}";
        }

        private sealed record AuthPayload
        {
            [JsonInclude]
            [JsonPropertyName("challenge")]
            public required string Challenge { get; init; }

            [JsonInclude]
            [JsonPropertyName("login_uri")]
            public required string LoginUri { get; init; }

            [JsonInclude]
            [JsonPropertyName("get_signing_certificate")]
            public bool? GetSigningCertificate { get; init; }
        }

        private sealed record AuthUri
        {
            [JsonInclude]
            [JsonPropertyName("auth_uri")]
            public required string AuthUriValue { get; init; }
        }
    }
}

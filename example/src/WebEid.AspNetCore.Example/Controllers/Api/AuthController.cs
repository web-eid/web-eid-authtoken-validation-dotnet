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
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Http;
    using Security.Util;
    using Security.Validator;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Security.Challenge;
    using WebEid.AspNetCore.Example.Dto;
    using WebEid.Security.AuthToken;
    using System;

    [Route("[controller]")]
    [ApiController]
    public class AuthController : BaseController
    {
        private readonly IAuthTokenValidator authTokenValidator;
        private readonly IChallengeNonceStore challengeNonceStore;

        public AuthController(IAuthTokenValidator authTokenValidator, IChallengeNonceStore challengeNonceStore)
        {
            this.authTokenValidator = authTokenValidator;
            this.challengeNonceStore = challengeNonceStore;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] AuthenticateRequestDto dto)
        {
            try
            {
                await SignInUser(dto?.AuthToken);
                return Ok();
            }
            catch (ArgumentNullException)
            {
                return BadRequest(new { error = "Missing auth_token" });
            }
        }

        [HttpPost("logout")]
        public async Task Logout()
        {
            RemoveUserContainerFile();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        private async Task SignInUser(WebEidAuthToken authToken)
        {
            if (authToken == null)
            {
                throw new ArgumentNullException(nameof(authToken), "authToken must not be null");
            }

            var certificate = await authTokenValidator.Validate(authToken, challengeNonceStore.GetAndRemove().Base64EncodedNonce);
            var claims = new List<Claim>();

            AddNewClaimIfCertificateHasData(claims, ClaimTypes.GivenName, certificate.GetSubjectGivenName);
            AddNewClaimIfCertificateHasData(claims, ClaimTypes.Surname, certificate.GetSubjectSurname);
            AddNewClaimIfCertificateHasData(claims, ClaimTypes.NameIdentifier, certificate.GetSubjectIdCode);
            AddNewClaimIfCertificateHasData(claims, ClaimTypes.Name, certificate.GetSubjectCn);

            var isV11 = authToken.Format?.StartsWith("web-eid:1.1", StringComparison.OrdinalIgnoreCase) == true;

            if (isV11 && !string.IsNullOrEmpty(authToken.UnverifiedSigningCertificate))
            {
                claims.Add(new Claim(
                    "signingCertificate",
                    authToken.UnverifiedSigningCertificate));
            }

            if (authToken.SupportedSignatureAlgorithms != null)
            {
                claims.Add(new Claim(
                    "supportedSignatureAlgorithms",
                    JsonSerializer.Serialize(authToken.SupportedSignatureAlgorithms)));
            }

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity),
                new AuthenticationProperties { AllowRefresh = true });
            
            // Assign a unique ID within the session to enable the use of a unique temporary container name across successive requests.
            // A unique temporary container name is required to facilitate simultaneous signing from multiple browsers.
            SetUniqueIdInSession();
        }

        private static void AddNewClaimIfCertificateHasData(List<Claim> claims, string claimType, Func<string> dataGetter) 
        {
            var claimData = dataGetter();
            if (!string.IsNullOrEmpty(claimData))
            {
                claims.Add(new Claim(claimType, claimData));
            }
        }
    }
}

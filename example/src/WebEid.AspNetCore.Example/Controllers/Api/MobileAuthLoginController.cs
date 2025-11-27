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

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using Microsoft.AspNetCore.Mvc;
    using System.Text.Json;
    using Dto;
    using Security.Challenge;
    using Security.Validator;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Security.Util;

    [ApiController]
    [Route("auth/mobile")]
    public class MobileAuthLoginController(
        IAuthTokenValidator authTokenValidator,
        IChallengeNonceStore challengeNonceStore
    ) : ControllerBase
    {
        [HttpPost("login")]
        public async Task<IActionResult> MobileLogin([FromBody] AuthenticateRequestDto dto)
        {
            if (dto?.AuthToken == null)
            {
                return BadRequest(new { error = "Missing auth_token" });
            }

            var parsedToken = dto.AuthToken;
            var certificate = await authTokenValidator.Validate(
                parsedToken,
                challengeNonceStore.GetAndRemove().Base64EncodedNonce);

            var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);

            identity.AddClaim(new Claim(ClaimTypes.GivenName, certificate.GetSubjectGivenName()));
            identity.AddClaim(new Claim(ClaimTypes.Surname, certificate.GetSubjectSurname()));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, certificate.GetSubjectIdCode()));
            identity.AddClaim(new Claim(ClaimTypes.Name, certificate.GetSubjectCn()));

            if (!string.IsNullOrEmpty(parsedToken.UnverifiedSigningCertificate))
            {
                identity.AddClaim(new Claim("signingCertificate", parsedToken.UnverifiedSigningCertificate));
            }

            if (parsedToken.SupportedSignatureAlgorithms != null)
            {
                identity.AddClaim(new Claim(
                    "supportedSignatureAlgorithms",
                    JsonSerializer.Serialize(parsedToken.SupportedSignatureAlgorithms)));
            }

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity),
                new AuthenticationProperties { IsPersistent = false });

            return Ok(new { redirect = "/welcome" });
        }
    }
}
// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Security.Challenge;
    using Security.Util;
    using Security.Validator;
    using WebEid.AspNetCore.Example.Dto;
    using WebEid.Security.AuthToken;
    using WebEid.Security.Exceptions;

    [Route("[controller]")]
    [ApiController]
    public class AuthController(IAuthTokenValidator authTokenValidator, IChallengeNonceStore challengeNonceStore) : BaseController
    {
        private readonly IAuthTokenValidator authTokenValidator = authTokenValidator;
        private readonly IChallengeNonceStore challengeNonceStore = challengeNonceStore;

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] AuthenticateRequestDto dto)
        {
            if (dto?.AuthToken is null)
            {
                return BadRequest(new { error = "Missing auth_token" });
            }

            try
            {
                await SignInUser(dto.AuthToken);
                return Ok();
            }
            catch (Exception ex) when (ex is ChallengeNonceNotFoundException or ChallengeNonceExpiredException)
            {
                return Unauthorized(new { error = "challenge_nonce_not_found_or_expired" });
            }
            catch (AuthTokenException)
            {
                return Unauthorized(new { error = "authentication_failed" });
            }
        }

        [HttpPost("logout")]
        public async Task Logout()
        {
            if (HasActiveSession())
            {
                RemoveUserContainerFile();
            }

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

            var signingCertificate = authToken.UnverifiedSigningCertificates != null &&
                                     authToken.UnverifiedSigningCertificates.Count > 0
                ? authToken.UnverifiedSigningCertificates[0]
                : null;

            if (signingCertificate != null && !string.IsNullOrEmpty(signingCertificate.Certificate))
            {
                claims.Add(new Claim(
                    "signingCertificate",
                    signingCertificate.Certificate));
            }

            if (signingCertificate?.SupportedSignatureAlgorithms != null)
            {
                claims.Add(new Claim(
                    "supportedSignatureAlgorithms",
                    JsonSerializer.Serialize(signingCertificate.SupportedSignatureAlgorithms)));
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

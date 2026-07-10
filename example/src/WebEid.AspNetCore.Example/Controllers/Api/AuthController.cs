// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Mvc;
    using Security.Util;
    using Security.Validator;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Security.Challenge;
    using WebEid.AspNetCore.Example.Dto;
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

        [HttpPost]
        [Route("login")]
        public async Task Login([FromBody] AuthenticateRequestDto authToken)
        {
            var certificate = await this.authTokenValidator.Validate(authToken.AuthToken, this.challengeNonceStore.GetAndRemove().Base64EncodedNonce);

            List<Claim> claims = new();

            AddNewClaimIfCertificateHasData(claims, ClaimTypes.GivenName, certificate.GetSubjectGivenName);
            AddNewClaimIfCertificateHasData(claims, ClaimTypes.Surname, certificate.GetSubjectSurname);
            AddNewClaimIfCertificateHasData(claims, ClaimTypes.NameIdentifier, certificate.GetSubjectIdCode);
            AddNewClaimIfCertificateHasData(claims, ClaimTypes.Name, certificate.GetSubjectCn);

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                AllowRefresh = true
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);
            
            // Assign a unique ID within the session to enable the use of a unique temporary container name across successive requests.
            // A unique temporary container name is required to facilitate simultaneous signing from multiple browsers.
            SetUniqueIdInSession();
        }

        [HttpGet]
        [Route("logout")]
        public async Task Logout()
        {
            RemoveUserContainerFile();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
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

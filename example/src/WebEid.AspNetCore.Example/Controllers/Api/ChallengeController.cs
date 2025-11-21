// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using Microsoft.AspNetCore.Mvc;
    using Security.Challenge;
    using WebEid.AspNetCore.Example.Dto;

    [Route("auth")]
    [ApiController]
    public class ChallengeController(IChallengeNonceGenerator challengeNonceGenerator) : BaseController
    {
        private readonly IChallengeNonceGenerator challengeNonceGenerator = challengeNonceGenerator;

        [HttpGet]
        [Route("challenge")]
        public ChallengeDto GetChallenge()
        {
            var challenge = new ChallengeDto
            {
                Nonce = challengeNonceGenerator.GenerateAndStoreNonce(TimeSpan.FromMinutes(5)).Base64EncodedNonce
            };
            return challenge;
        }
    }
}

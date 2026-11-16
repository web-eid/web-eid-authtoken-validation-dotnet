// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example
{
    using System;
    using System.Text.Json;
    using Microsoft.AspNetCore.Http;
    using WebEid.Security.Challenge;

    public class SessionBackedChallengeNonceStore(IHttpContextAccessor httpContextAccessor) : IChallengeNonceStore
    {
        private const string ChallengeNonceKey = "challenge-nonce";
        private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;

        public void Put(ChallengeNonce challengeNonce)
        {
            var httpContext = httpContextAccessor.HttpContext
                ?? throw new InvalidOperationException("HttpContext is not available.");

            httpContext.Session.SetString(ChallengeNonceKey, JsonSerializer.Serialize(challengeNonce));
        }

        public ChallengeNonce? GetAndRemoveImpl()
        {
            var httpContext = httpContextAccessor.HttpContext;
            if (httpContext is null)
            {
                return null;
            }

            var challengeNonceJson = httpContext.Session.GetString(ChallengeNonceKey);
            if (!string.IsNullOrWhiteSpace(challengeNonceJson))
            {
                httpContext.Session.Remove(ChallengeNonceKey);
                return JsonSerializer.Deserialize<ChallengeNonce>(challengeNonceJson);
            }
            return null;
        }
    }
}

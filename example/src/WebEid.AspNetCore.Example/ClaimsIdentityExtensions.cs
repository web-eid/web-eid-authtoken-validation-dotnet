// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example
{
    using System.Linq;
    using System.Security.Claims;

    public static class ClaimsIdentityExtensions
    {
        public static string? GetIdCode(this ClaimsIdentity identity) => identity.Claims.SingleOrDefault(claim => claim.Type == ClaimTypes.NameIdentifier)?.Value;
    }
}

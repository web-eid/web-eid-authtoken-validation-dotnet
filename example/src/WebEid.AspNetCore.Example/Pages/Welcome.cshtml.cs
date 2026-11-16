// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Pages
{
    using System.Linq;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    public class WelcomeModel : PageModel
    {
        public string PrincipalName => GetPrincipalName(User.Identity as ClaimsIdentity);

        private static string GetPrincipalName(ClaimsIdentity? identity)
        {
            if (identity is null)
            {
                return string.Empty;
            }

            var givenName = identity.Claims.Where(claim => claim.Type == ClaimTypes.GivenName)
                .Select(claim => claim.Value)
                .SingleOrDefault();
            var surname = identity.Claims.Where(claim => claim.Type == ClaimTypes.Surname)
                .Select(claim => claim.Value)
                .SingleOrDefault();

            if (!string.IsNullOrEmpty(givenName) && !string.IsNullOrEmpty(surname))
            {
                return $"{givenName} {surname}";
            }

            return identity.Claims.Where(claim => claim.Type == ClaimTypes.Name)
                .Select(claim => claim.Value)
                .SingleOrDefault() ?? string.Empty;
        }
    }
}

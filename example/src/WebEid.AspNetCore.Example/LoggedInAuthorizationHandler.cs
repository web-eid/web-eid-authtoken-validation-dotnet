// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;

    public class LoggedInAuthorizationHandler : AuthorizationHandler<LoggedInRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, LoggedInRequirement requirement)
        {
            if (context.User.Identity?.IsAuthenticated == true)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }

    public class LoggedInRequirement : IAuthorizationRequirement { }
}

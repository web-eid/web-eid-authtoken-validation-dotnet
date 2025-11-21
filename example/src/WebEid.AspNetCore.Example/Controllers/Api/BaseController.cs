// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;

    public abstract class BaseController : ControllerBase
    {
        private const string UniqueIdKey = "UniqueId";

        protected void RemoveUserContainerFile() => System.IO.File.Delete(GetUserContainerName());

        protected void SetUniqueIdInSession() => HttpContext.Session.SetString(UniqueIdKey, Guid.NewGuid().ToString());

        protected bool HasActiveSession() => GetUniqueIdFromSession() is not null;

        protected UnauthorizedObjectResult SessionExpired() => Unauthorized(new { error = "session_expired" });

        private string? GetUniqueIdFromSession() => HttpContext.Session.GetString(UniqueIdKey);

        protected string GetUserContainerName() => $"container_{GetUniqueIdFromSession()}";
    }
}

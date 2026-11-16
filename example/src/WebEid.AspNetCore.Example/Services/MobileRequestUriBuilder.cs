// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Services
{
    using System;
    using Microsoft.Extensions.Options;
    using Options;

    public class MobileRequestUriBuilder(IOptions<WebEidMobileOptions> options)
    {
        private readonly string baseUri = options.Value.BaseRequestUri;

        public string Build(string path, string encodedPayload) => baseUri.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? $"{baseUri.TrimEnd('/')}/{path}#{encodedPayload}"
                : $"{baseUri}{path}#{encodedPayload}";
    }
}

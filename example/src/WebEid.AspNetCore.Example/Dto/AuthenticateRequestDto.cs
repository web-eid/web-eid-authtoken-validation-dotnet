// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

﻿namespace WebEid.AspNetCore.Example.Dto
{
    using System.Text.Json.Serialization;
    using Security.AuthToken;

    public class AuthenticateRequestDto
    {
        [JsonPropertyName("auth-token")]
        public WebEidAuthToken AuthToken { get; set; }
    }
}

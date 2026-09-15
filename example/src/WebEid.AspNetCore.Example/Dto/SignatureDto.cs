// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

﻿namespace WebEid.AspNetCore.Example.Dto
{
    public class SignatureDto
    {
        public SignatureAlgorithmDto SignatureAlgorithm { get; set; }

        /// <summary>
        /// Base64 signature
        /// </summary>
        public string Signature { get; set; }
    }
}
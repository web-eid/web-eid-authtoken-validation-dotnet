// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

﻿namespace WebEid.AspNetCore.Example.Dto
{
    public class DigestDto
    {
        public string Hash { get; set; }
        public string HashFunction { get; set; }
    }
}
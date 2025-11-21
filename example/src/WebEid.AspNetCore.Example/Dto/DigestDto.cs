// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Dto
{
    public class DigestDto
    {
        public required string Hash { get; set; }
        public required string HashFunction { get; set; }
    }
}

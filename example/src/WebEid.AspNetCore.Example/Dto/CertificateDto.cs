// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Dto
{
    using System.Collections.Generic;
    using System.Text.Json.Serialization;

    public class CertificateDto
    {
        [JsonPropertyName("certificate")]
        public required string CertificateBase64String { get; set; }
        public required IList<SignatureAlgorithmDto> SupportedSignatureAlgorithms { get; set; }
    }
}

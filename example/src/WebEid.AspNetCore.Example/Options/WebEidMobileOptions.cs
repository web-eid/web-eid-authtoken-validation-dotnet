// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Options
{
    using System.ComponentModel.DataAnnotations;

    public class WebEidMobileOptions
    {
        [Required]
        [RegularExpression("^.*(?:[^/]|://)$", ErrorMessage = "Base URI must not have a trailing slash")]
        public string BaseRequestUri { get; set; } = null!;

        public bool RequestSigningCert { get; set; }
    }
}

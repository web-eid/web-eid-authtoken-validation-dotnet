// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using System.IO;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Dto;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Services;
    using Signing;

    [Route("[controller]")]
    [ApiController]
    [Authorize(Policy = "LoggedInOnly")]
    public class SignController(SigningService signingService, MobileSigningService mobileSigningService) : BaseController
    {
        private const string SignedFile = "example-for-signing.asice";
        private readonly SigningService signingService = signingService;
        private readonly MobileSigningService mobileSigningService = mobileSigningService;

        [HttpPost("prepare")]
        public ActionResult<DigestDto> Prepare([FromBody] CertificateDto data)
        {
            if (!HasActiveSession())
            {
                return SessionExpired();
            }

            var identity = HttpContext.User.Identity as ClaimsIdentity
                ?? throw new InvalidOperationException("User identity is missing or invalid.");

            try
            {
                return signingService.PrepareContainer(data, identity, GetUserContainerName());
            }
            catch (ArgumentException)
            {
                return BadRequest(new { error = "signing_certificate_mismatch" });
            }
        }

        [HttpPost("sign")]
        public ActionResult<FileDto> Sign([FromBody] SignatureDto data)
        {
            if (!HasActiveSession())
            {
                return SessionExpired();
            }

            signingService.SignContainer(data, GetUserContainerName());
            return new FileDto(SignedFile);
        }

        [HttpPost("mobile/init")]
        public ActionResult<MobileSigningService.MobileInitRequest> MobileInit()
        {
            if (!HasActiveSession())
            {
                return SessionExpired();
            }

            var identity = HttpContext.User.Identity as ClaimsIdentity
                ?? throw new InvalidOperationException("User identity is missing or invalid.");

            var container = GetUserContainerName();

            try
            {
                return mobileSigningService.InitCertificateOrSigningRequest(identity, container);
            }
            catch (ArgumentException)
            {
                return BadRequest(new { error = "signing_certificate_mismatch" });
            }
        }

        [HttpPost("mobile/certificate")]
        public ActionResult<MobileSigningService.MobileInitRequest> CertificatePost([FromBody] CertificateDto certificateDto)
        {
            if (!HasActiveSession())
            {
                return SessionExpired();
            }

            var identity = HttpContext.User.Identity as ClaimsIdentity
                ?? throw new InvalidOperationException("User identity is missing or invalid.");

            var containerName = GetUserContainerName();

            try
            {
                return mobileSigningService.InitSigningRequest(identity, certificateDto, containerName);
            }
            catch (ArgumentException)
            {
                return BadRequest(new { error = "signing_certificate_mismatch" });
            }
        }

        [HttpPost("mobile/signature")]
        public ActionResult<FileDto> SignaturePost([FromBody] SignatureDto signatureDto)
        {
            if (!HasActiveSession())
            {
                return SessionExpired();
            }

            signingService.SignContainer(signatureDto, GetUserContainerName());
            return new FileDto(SignedFile);
        }

        [HttpGet("download")]
        public async Task<IActionResult> Download()
        {
            if (!HasActiveSession())
            {
                return SessionExpired();
            }

            try
            {
                var content = await System.IO.File.ReadAllBytesAsync(GetUserContainerName());
                return File(content, "application/vnd.etsi.asic-e+zip", SignedFile);
            }
            catch (InvalidOperationException)
            {
                return SessionExpired();
            }
            catch (FileNotFoundException)
            {
                return NotFound();
            }
        }
    }
}

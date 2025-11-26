// Copyright (c) 2021-2024 Estonian Information System Authority
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

namespace WebEid.AspNetCore.Example.Controllers.Api
{
    using System;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Dto;
    using Services;
    using Signing;

    [Route("[controller]")]
    [ApiController]
    public class SignController : BaseController
    {
        private const string SignedFile = "example-for-signing.asice";
        private readonly SigningService signingService;
        private readonly MobileSigningService mobileSigningService;
        private readonly ILogger logger;

        public SignController(SigningService signingService, MobileSigningService mobileSigningService, ILogger logger)
        {
            this.signingService = signingService;
            this.mobileSigningService = mobileSigningService;
            this.logger = logger;
        }

        [Route("prepare")]
        [HttpPost]
        public DigestDto Prepare([FromBody] CertificateDto data)
        {
            return signingService.PrepareContainer(data, (ClaimsIdentity)HttpContext.User.Identity, GetUserContainerName());
        }

        [Route("sign")]
        [HttpPost]
        public FileDto Sign([FromBody] SignatureDto data)
        {
            signingService.SignContainer(data, GetUserContainerName());
            return new FileDto(SignedFile);
        }

        [HttpPost("mobile/init")]
        public MobileSigningService.MobileInitRequest MobileInit()
        {
            var identity = (ClaimsIdentity)HttpContext.User.Identity;
            var container = GetUserContainerName();
            return mobileSigningService.InitCertificateOrSigningRequest(identity, container);
        }

        [Route("sign/mobile/certificate")]
        [HttpGet]
        public IActionResult CertificateResponse()
        {
            return Redirect("/sign/mobile/certificate");
        }

        [Route("mobile/certificate")]
        [HttpPost]
        public MobileSigningService.MobileInitRequest CertificatePost([FromBody] CertificateDto certificateDto)
        {
            var identity = (ClaimsIdentity)HttpContext.User.Identity;
            var containerName = GetUserContainerName();

            return mobileSigningService.InitSigningRequest(
                identity,
                certificateDto,
                containerName);
        }

        [Route("sign/mobile/signature")]
        [HttpGet]
        public IActionResult SignatureResponse()
        {
            return Redirect("/sign/mobile/signature");
        }

        [Route("mobile/signature")]
        [HttpPost]
        public FileDto SignaturePost([FromBody] SignatureDto signatureDto)
        {
            signingService.SignContainer(signatureDto, GetUserContainerName());
            return new FileDto(SignedFile);
        }

        [Route("download")]
        [HttpGet]
        public async Task<IActionResult> Download()
        {
            try
            {
                var content = await System.IO.File.ReadAllBytesAsync(GetUserContainerName());
                return File(content, "application/vnd.etsi.asic-e+zip", SignedFile);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Error occurred while downloading user container file");
                return BadRequest();
            }
        }
    }
}

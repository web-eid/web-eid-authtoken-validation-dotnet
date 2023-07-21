/*
 * Copyright © 2020-2023 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
namespace WebEid.Security.Validator.CertValidators
{
    using System;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Ocsp;
    using Ocsp.Service;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Ocsp;
    using Org.BouncyCastle.Ocsp;
    using Org.BouncyCastle.Security;

    internal sealed class SubjectCertificateNotRevokedValidator : ISubjectCertificateValidator
    {
        private readonly SubjectCertificateTrustedValidator trustValidator;
        private readonly IOcspClient ocspClient;
        private readonly OcspServiceProvider ocspServiceProvider;
        private readonly ILogger logger;

        public SubjectCertificateNotRevokedValidator(SubjectCertificateTrustedValidator trustValidator,
            IOcspClient ocspClient,
            OcspServiceProvider ocspServiceProvider,
            ILogger logger = null)
        {
            this.trustValidator = trustValidator;
            this.ocspClient = ocspClient;
            this.ocspServiceProvider = ocspServiceProvider;
            this.logger = logger;
        }

        /// <summary>
        /// Validates that the user certificate from the authentication token is not revoked with OCSP.
        /// </summary>
        /// <param name="subjectCertificate">the user certificate to be validated.</param>
        /// <exception cref="AuthTokenException">when user certificate is revoked or revocation check fails.</exception>
        public async Task Validate(X509Certificate2 subjectCertificate)
        {
            try
            {
                var certificate = DotNetUtilities.FromX509Certificate(subjectCertificate);
                var ocspService = this.ocspServiceProvider.GetService(certificate);

                if (!ocspService.DoesSupportNonce)
                {
                    this.logger?.LogDebug("Disabling OCSP nonce extension");
                }

                var certificateId = new CertificateID(CertificateID.HashSha1,
                    DotNetUtilities.FromX509Certificate(this.trustValidator.SubjectCertificateIssuerCertificate),
                    certificate.SerialNumber);

                var request = new OcspRequestBuilder()
                    .EnableOcspNonce(ocspService.DoesSupportNonce)
                    .WithCertificateId(certificateId)
                    .Build();

                this.logger?.LogDebug("Sending OCSP request");
                var response = await this.ocspClient.Request(ocspService.AccessLocation, request);
                if (response.Status != OcspResponseStatus.Successful)
                {
                    throw new UserCertificateOcspCheckFailedException(
                        $"Response status: {OcspStatusToString(response.Status)}");
                }

                var basicOcspResponse = (BasicOcspResp)response.GetResponseObject();
                this.VerifyOcspResponse(basicOcspResponse, ocspService, certificateId);
                if (ocspService.DoesSupportNonce)
                {
                    VerifyOcspResponseNonce(request, basicOcspResponse);
                }
            }
            catch (Exception ex) when (!(ex is UserCertificateOcspCheckFailedException))
            {
                throw new UserCertificateOcspCheckFailedException(ex);
            }
        }

        private void VerifyOcspResponse(BasicOcspResp basicResponse,
            IOcspService ocspService,
            CertificateID requestCertificateId)
        {
            // The verification algorithm follows RFC 2560, https://www.ietf.org/rfc/rfc2560.txt.
            //
            // 3.2.  Signed Response Acceptance Requirements
            //   Prior to accepting a signed response for a particular certificate as
            //   valid, OCSP clients SHALL confirm that:
            //
            //   1. The certificate identified in a received response corresponds to
            //      the certificate that was identified in the corresponding request.

            // As we sent the request for only a single certificate, we expect only a single response.
            if (basicResponse.Responses.Length != 1)
            {
                throw new UserCertificateOcspCheckFailedException(
                    $"OCSP response must contain one response, received {basicResponse.Responses.Length} responses instead");
            }
            var certStatusResponse = basicResponse.Responses[0];
            if (!requestCertificateId.SerialNumber.Equals(certStatusResponse.GetCertID().SerialNumber))
            {
                throw new UserCertificateOcspCheckFailedException(
                    "OCSP responded with certificate ID that differs from the requested ID");
            }

            //   2. The signature on the response is valid.
            // We assume that the responder includes its certificate in the certs field of the response
            // that helps us to verify it. According to RFC 2560 this field is optional, but including it
            // is standard practice.
            // There may be multiple responder certificates, but at least one must be presented.
            var responseCertificates = basicResponse.GetCerts();
            if (responseCertificates.Length < 1)
            {
                throw new UserCertificateOcspCheckFailedException("OCSP response must contain the responder certificate, but none was provided");
            }

            // Validate responder certificates. At least one must be valid.
            Org.BouncyCastle.X509.X509Certificate responderCert = null;
            Exception lastValidationException = null;
            foreach (var cert in responseCertificates)
            {
                try
                {
                    OcspResponseValidator.ValidateResponseSignature(basicResponse, cert);
                    responderCert = cert;
                    lastValidationException = null;
                    break;
                }
                catch (UserCertificateOcspCheckFailedException ex)
                {
                    lastValidationException = ex;
                }
            }

            // If validation of all certificates failed, throw the last validation exception.
            if (lastValidationException != null)
            {
                throw lastValidationException;
            }

            //   3. The identity of the signer matches the intended recipient of the
            //      request.
            //
            //   4. The signer is currently authorized to provide a response for the
            //      certificate in question.

            var producedAt = basicResponse.ProducedAt;
            ocspService.ValidateResponderCertificate(responderCert, producedAt);

            //   5. The time at which the status being indicated is known to be
            //      correct (thisUpdate) is sufficiently recent.
            //
            //   6. When available, the time at or before which newer information will
            //      be available about the status of the certificate (nextUpdate) is
            //      greater than the current time.

            OcspResponseValidator.ValidateCertificateStatusUpdateTime(certStatusResponse, producedAt);

            // Now we can accept the signed response as valid and validate the certificate status.
            OcspResponseValidator.ValidateOcspResponseStatus(certStatusResponse);

            this.logger?.LogDebug("OCSP check result is GOOD");
        }

        private static void VerifyOcspResponseNonce(OcspReq request, BasicOcspResp response)
        {
            Asn1OctetString responseNonceValue;
            try
            {
                responseNonceValue = response.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
            }
            catch (IOException ex)
            {
                throw new OcspException("Can't parse OCSP nonce extension from response", ex);
            }

            if (responseNonceValue == null)
            {
                throw new OcspException("Nonce was sent and is required but did not get it in reply");
            }

            Asn1OctetString requestNonceValue;
            try
            {
                requestNonceValue = request.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
            }
            catch (Exception ex)
            {
                throw new OcspException("Nonce received with the reply is invalid, unable to parse it", ex);
            }

            if (!responseNonceValue.Equals(requestNonceValue))
            {
                throw new OcspException("Received nonce doesn't match the one sent to the server.");
            }
        }

        private static string OcspStatusToString(int status) => status switch
        {
            OcspResponseStatus.MalformedRequest => "malformed request",
            OcspResponseStatus.InternalError => "internal error",
            OcspResponseStatus.TryLater => "service unavailable",
            OcspResponseStatus.SignatureRequired => "request signature missing",
            OcspResponseStatus.Unauthorized => "unauthorized",
            _ => "unknown",
        };
    }
}

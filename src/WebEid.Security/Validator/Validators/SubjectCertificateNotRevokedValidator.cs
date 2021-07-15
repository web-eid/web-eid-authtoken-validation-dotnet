namespace WebEid.Security.Validator.Validators
{
    using System;
    using System.IO;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Ocsp;
    using Ocsp.Service;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Ocsp;
    using Org.BouncyCastle.Ocsp;
    using Org.BouncyCastle.Pkix;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Security.Certificates;

    internal sealed class SubjectCertificateNotRevokedValidator : IValidator
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
        /// <param name="actualTokenData">authentication token data that contains the user certificate.</param>
        /// <exception cref="TokenValidationException">when user certificate is revoked.</exception>
        public async Task Validate(AuthTokenValidatorData actualTokenData)
        {
            try
            {
                var certificate = DotNetUtilities.FromX509Certificate(actualTokenData.SubjectCertificate);
                var ocspService = this.ocspServiceProvider.GetService(certificate);

                if (ocspService.DoesSupportNonce)
                {
                    this.logger?.LogDebug("Disabling OCSP nonce extension");
                }

                var certificateId = new CertificateID(CertificateID.HashSha1,
                    DotNetUtilities.FromX509Certificate(this.trustValidator.SubjectCertificateIssuerCertificate),
                    certificate.SerialNumber);

                var request = new OcspRequestBuilder()
                    .EnableOcspNonce(!ocspService.DoesSupportNonce)
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
            catch (HttpRequestException ex)
            {
                throw new UserCertificateOcspCheckFailedException(ex);
            }
            catch (CertificateEncodingException ex)
            {
                throw new UserCertificateOcspCheckFailedException(ex);
            }
            catch (OcspException ex)
            {
                throw new UserCertificateOcspCheckFailedException(ex);
            }
            catch (IOException ex)
            {
                throw new UserCertificateOcspCheckFailedException(ex);
            }
            catch (PkixCertPathValidatorException ex)
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
            var responseCertificates = basicResponse.GetCerts();
            if (responseCertificates.Length != 1)
            {
                throw new UserCertificateOcspCheckFailedException(
                    $"OCSP response must contain one responder certificate, received {responseCertificates.Length} certificates instead");
            }
            var responderCert = basicResponse.GetCerts()[0];
            OcspResponseValidator.ValidateResponseSignature(basicResponse, responderCert);

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

        private static string OcspStatusToString(int status)
        {
            switch (status)
            {
                case OcspResponseStatus.MalformedRequest:
                    return "malformed request";
                case OcspResponseStatus.InternalError:
                    return "internal error";
                case OcspResponseStatus.TryLater:
                    return "service unavailable";
                case OcspResponseStatus.SignatureRequired:
                    return "request signature missing";
                case OcspResponseStatus.Unauthorized:
                    return "unauthorized";
            }
            return "unknown";
        }
    }
}

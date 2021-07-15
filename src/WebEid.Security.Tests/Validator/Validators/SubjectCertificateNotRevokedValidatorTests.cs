namespace WebEid.Security.Tests.Validator.Validators
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Net.Http;
    using System.Reflection;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using NUnit.Framework;
    using Org.BouncyCastle.Asn1.Ocsp;
    using Org.BouncyCastle.Ocsp;
    using Security.Validator;
    using Security.Validator.Ocsp;
    using Security.Validator.Validators;
    using TestUtils;

    [TestFixture]
    public sealed class SubjectCertificateNotRevokedValidatorTests : IDisposable
    {
        private readonly OcspClient ocspClient;
        private SubjectCertificateTrustedValidator trustedValidator;
        private AuthTokenValidatorData authTokenValidatorWithEsteid2018Cert;

        public SubjectCertificateNotRevokedValidatorTests()
        {
            this.ocspClient = new OcspClient(TimeSpan.FromSeconds(5));
        }

        [SetUp]
        public void SetUp()
        {
            this.trustedValidator = new SubjectCertificateTrustedValidator(null);
            SetSubjectCertificateIssuerCertificate(this.trustedValidator);
            this.authTokenValidatorWithEsteid2018Cert = new AuthTokenValidatorData(Certificates.GetJaakKristjanEsteid2018Cert());
        }

        [Test]
        public void WhenValidAiaOcspResponderConfigurationThenSucceeds()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(this.ocspClient);
            Assert.DoesNotThrow(() =>
                validator.Validate(this.authTokenValidatorWithEsteid2018Cert));
        }

        [Test]
        public void WhenValidDesignatedOcspResponderConfigurationThenSucceeds()
        {
            var ocspServiceProvider = OcspServiceMaker.GetDesignatedOcspServiceProvider();
            var validator =
                new SubjectCertificateNotRevokedValidator(this.trustedValidator, this.ocspClient, ocspServiceProvider);
            Assert.DoesNotThrow(() => validator.Validate(this.authTokenValidatorWithEsteid2018Cert));
        }

        [Test]
        public void WhenValidOcspNonceDisabledConfigurationThenSucceeds()
        {
            var ocspServiceProvider = OcspServiceMaker.GetDesignatedOcspServiceProvider(false);
            var validator =
                new SubjectCertificateNotRevokedValidator(this.trustedValidator, this.ocspClient, ocspServiceProvider);
            Assert.DoesNotThrow(() => validator.Validate(this.authTokenValidatorWithEsteid2018Cert));
        }

        [Test]
        public void WhenOcspUrlIsInvalidThenThrows()
        {
            var ocspServiceProvider = OcspServiceMaker.GetDesignatedOcspServiceProvider("http://invalid.invalid");
            var validator =
                new SubjectCertificateNotRevokedValidator(this.trustedValidator, this.ocspClient, ocspServiceProvider);
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .InnerException
                .HasMessageStartingWith("No such host is known. (invalid.invalid:80)");
        }

        [Test]
        public void WhenOcspRequestFailsThenThrows()
        {
            var ocspServiceProvider =
                OcspServiceMaker.GetDesignatedOcspServiceProvider("https://web-eid-test.free.beeceptor.com");
            var validator = new SubjectCertificateNotRevokedValidator(this.trustedValidator, this.ocspClient, ocspServiceProvider);
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .InnerException
                .HasMessageStartingWith("OCSP request was not successful, response:");
        }

        [Test]
        public void WhenOcspRequestHasInvalidBodyThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(new OcspClientMock("invalid"));
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .InnerException
                .HasMessage("corrupted stream - out of bounds length found: 110 >= 7");
        }

        [Test]
        public void WhenOcspResponseIsNotSuccessfulThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                new OcspClientMock(BuildOcspResponseBodyWithInternalErrorStatus()));
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .WithMessage("User certificate revocation check has failed: Response status: internal error");
        }

        [Test]
        public void WhenOcspResponseHasInvalidCertificateIdThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                new OcspClientMock(BuildOcspResponseBodyWithInvalidCertificateId()));
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .WithMessage(
                    "User certificate revocation check has failed: OCSP responded with certificate ID that differs from the requested ID");
        }

        [Test]
        public void WhenOcspResponseHasInvalidSignatureThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                new OcspClientMock(BuildOcspResponseBodyWithInvalidSignature()));
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .WithMessage("User certificate revocation check has failed: OCSP response signature is invalid");
        }

        [Test]
        public void WhenOcspResponseHasInvalidResponderCertThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                new OcspClientMock(BuildOcspResponseBodyWithInvalidResponderCert()));
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .InnerException
                .IsInstanceOf<IOException>()
                .HasMessageStartingWith("corrupted stream - out of bounds length found: 322 >= 270");
        }

        [Test]
        public void WhenOcspResponseHasInvalidTagThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                new OcspClientMock(BuildOcspResponseBodyWithInvalidTag()));
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .InnerException
                .IsInstanceOf<OcspException>()
                .HasMessage("problem decoding object: System.IO.IOException: unknown tag 23 encountered");
        }

        [Test]
        public void WhenOcspResponseHas2CertResponsesThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                new OcspClientMock(ResourceReader.ReadFromResource("ocsp_response_with_2_responses.der")));
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .WithMessage(
                    "User certificate revocation check has failed: OCSP response must contain one response, received 2 responses instead");
        }

        [Test]
        [Ignore("It is difficult to make Python and C# CertId equal, needs more work")]
        public void WhenOcspResponseHas2ResponderCertsThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                new OcspClientMock(ResourceReader.ReadFromResource("ocsp_response_with_2_responder_certs.der")));
            Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .WithMessage(
                    "User certificate revocation check has failed: OCSP response must contain one responder certificate, received 2 certificates instead");
        }

        [Test]
        public void WhenOcspResponseRevokedThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                    new OcspClientMock(ResourceReader.ReadFromResource("ocsp_response_revoked.der")));
            Assert.ThrowsAsync<UserCertificateRevokedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .WithMessage("User certificate has been revoked: Revocation reason: 0");
        }

        [Test]
        public void WhenOcspResponseUnknownThenThrows()
        {
            var ocspServiceProvider = OcspServiceMaker.GetDesignatedOcspServiceProvider("https://web-eid-test.free.beeceptor.com");
            var ocspClientMock = new OcspClientMock(ResourceReader.ReadFromResource("ocsp_response_unknown.der"));
            var validator = new SubjectCertificateNotRevokedValidator(this.trustedValidator, ocspClientMock, ocspServiceProvider);
            Assert.ThrowsAsync<UserCertificateRevokedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .WithMessage("User certificate has been revoked: Unknown status");
        }

        [Test]
        public void WhenOcspResponseCaNotTrustedThenThrows()
        {
            var validator = this.GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(
                new OcspClientMock(ResourceReader.ReadFromResource("ocsp_response_unknown.der")));
            Assert.ThrowsAsync<CertificateNotTrustedException>(() =>
                    validator.Validate(this.authTokenValidatorWithEsteid2018Cert))
                .WithMessage(
                    "Certificate E=pki@sk.ee, CN=TEST of SK OCSP RESPONDER 2020, OU=OCSP, O=AS Sertifitseerimiskeskus, C=EE is not trusted");
        }


        private static byte[] BuildOcspResponseBodyWithInternalErrorStatus()
        {
            var ocspResponseBytes = GetOcspResponseBytesFromResource();
            var statusOffset = 6;
            ocspResponseBytes[statusOffset] = OcspResponseStatus.InternalError;
            return ocspResponseBytes;
        }

        private static byte[] BuildOcspResponseBodyWithInvalidCertificateId()
        {
            var ocspResponseBytes = GetOcspResponseBytesFromResource();
            var certificateIdOffset = 234;
            ocspResponseBytes[certificateIdOffset + 3] = 0x42;
            return ocspResponseBytes;
        }

        private static byte[] BuildOcspResponseBodyWithInvalidSignature()
        {
            var ocspResponseBytes = GetOcspResponseBytesFromResource();
            var signatureOffset = 349;
            ocspResponseBytes[signatureOffset + 5] = 0x01;
            return ocspResponseBytes;
        }

        private static byte[] BuildOcspResponseBodyWithInvalidResponderCert()
        {
            var ocspResponseBytes = GetOcspResponseBytesFromResource();
            var certificateOffset = 935;
            ocspResponseBytes[certificateOffset + 3] = 0x42;
            return ocspResponseBytes;
        }

        private static byte[] BuildOcspResponseBodyWithInvalidTag()
        {
            var ocspResponseBytes = GetOcspResponseBytesFromResource();
            var tagOffset = 352;
            ocspResponseBytes[tagOffset] = 0x42;
            return ocspResponseBytes;
        }

        // Either write the bytes of a real OCSP response to a file or use Python and asn1crypto.ocsp
        // to create a mock response, see OCSPBuilder in https://github.com/wbond/ocspbuilder/blob/master/ocspbuilder/__init__.py.
        private static byte[] GetOcspResponseBytesFromResource()
        {
            return ResourceReader.ReadFromResource("ocsp_response.der");
        }

        private SubjectCertificateNotRevokedValidator GetSubjectCertificateNotRevokedValidatorWithAiaOcsp(IOcspClient client)
        {
            return new SubjectCertificateNotRevokedValidator(this.trustedValidator, client, OcspServiceMaker.GetAiaOcspServiceProvider());
        }

        private static void SetSubjectCertificateIssuerCertificate(SubjectCertificateTrustedValidator trustedValidator)
        {
            SetPrivatePropertyValue(trustedValidator, "SubjectCertificateIssuerCertificate", new X509Certificate2(Certificates.GetTestEsteid2018Ca()));
        }

        private static void SetPrivatePropertyValue<T>(object obj, string propName, T val)
        {
            var t = obj.GetType();
            if (t.GetProperty(propName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance) == null)
            {
                throw new ArgumentOutOfRangeException(nameof(propName),
                    $"Property {propName} was not found in Type {obj.GetType().FullName}");
            }

            t.InvokeMember(propName,
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.SetProperty | BindingFlags.Instance,
                null,
                obj,
                new object[] { val },
                CultureInfo.InvariantCulture);
        }

        private class OcspClientMock : IOcspClient
        {
            private HttpContent content;

            public OcspClientMock(byte[] content)
            {
                this.content = new ByteArrayContent(content);
            }

            public OcspClientMock(string content)
            {
                this.content = new StringContent(content);
            }

            public void Dispose() { }

            public async Task<OcspResp> Request(Uri uri, OcspReq ocspReq)
            {
                var contentBytes = await this.content.ReadAsByteArrayAsync();
                return new OcspResp(contentBytes);
            }
        }

        public void Dispose()
        {
            ocspClient?.Dispose();
        }
    }
}

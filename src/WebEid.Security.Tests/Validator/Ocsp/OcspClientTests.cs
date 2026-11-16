// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Tests.Validator.Ocsp
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using Org.BouncyCastle.Ocsp;
    using Security.Validator.Ocsp;

    [TestFixture]
    public class OcspClientTests
    {
        private const string OcspResponseType = "application/ocsp-response";

        [Test]
        public void WhenHttpResponseIsNotSuccessfulThenThrowsHttpRequestException()
        {
            using var listener = CreateListener(out var uri);
            var serverTask = RespondOnce(listener, HttpStatusCode.BadRequest, OcspResponseType, Encoding.UTF8.GetBytes("bad"));

            using var ocspClient = new OcspClient(TimeSpan.FromSeconds(5));
            var request = CreateOcspRequest();

            Assert.ThrowsAsync<HttpRequestException>(() => ocspClient.Request(uri, request));
            Assert.DoesNotThrowAsync(async () => await serverTask);
        }

        [Test]
        public void WhenResponseContentTypeIsInvalidThenThrowsIOException()
        {
            using var listener = CreateListener(out var uri);
            var serverTask = RespondOnce(listener, HttpStatusCode.OK, "text/plain", Encoding.UTF8.GetBytes("not-ocsp"));

            using var ocspClient = new OcspClient(TimeSpan.FromSeconds(5));
            var request = CreateOcspRequest();

            Assert.ThrowsAsync<IOException>(() => ocspClient.Request(uri, request));
            Assert.DoesNotThrowAsync(async () => await serverTask);
        }

        [Test]
        public void WhenResponseContentTypeIsOcspThenAttemptsToParseResponse()
        {
            using var listener = CreateListener(out var uri);
            var serverTask = RespondOnce(listener, HttpStatusCode.OK, OcspResponseType, Encoding.UTF8.GetBytes("not-a-valid-ocsp-response"));

            using var ocspClient = new OcspClient(TimeSpan.FromSeconds(5));
            var request = CreateOcspRequest();

            Assert.ThrowsAsync<IOException>(async () => _ = await ocspClient.Request(uri, request));

            Assert.DoesNotThrowAsync(async () => await serverTask);
        }

        [Test]
        public void WhenResponseContentTypeIsNullThenAttemptsToParseResponse()
        {
            using var listener = CreateListener(out var uri);
            var serverTask = RespondOnceWithoutContentType(listener, HttpStatusCode.OK, Encoding.UTF8.GetBytes("not-a-valid-ocsp-response"));

            using var ocspClient = new OcspClient(TimeSpan.FromSeconds(5));
            var request = CreateOcspRequest();

            Assert.ThrowsAsync<IOException>(async () => _ = await ocspClient.Request(uri, request));
            Assert.DoesNotThrowAsync(async () => await serverTask);
        }

        [Test]
        public void WhenDisposedThenDoesNotThrow()
        {
            var ocspClient = new OcspClient(TimeSpan.FromSeconds(5));

            Assert.DoesNotThrow(ocspClient.Dispose);
        }

        private static OcspReq CreateOcspRequest()
        {
            var generator = new OcspReqGenerator();
            return generator.Generate();
        }

        private static HttpListener CreateListener(out Uri uri)
        {
            var port = GetFreePort();
            var prefix = $"http://127.0.0.1:{port}/";
            var listener = new HttpListener();
            listener.Prefixes.Add(prefix);
            listener.Start();
            uri = new Uri(prefix);
            return listener;
        }

        private static async Task RespondOnce(HttpListener listener, HttpStatusCode statusCode, string contentType, byte[] body)
        {
            try
            {
                var context = await listener.GetContextAsync();
                context.Response.StatusCode = (int)statusCode;
                context.Response.ContentType = contentType;
                context.Response.ContentLength64 = body.Length;

                await context.Response.OutputStream.WriteAsync(body);
                context.Response.OutputStream.Close();
                context.Response.Close();
            }
            finally
            {
                listener.Stop();
            }
        }

        private static int GetFreePort()
        {
            var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            tcpListener.Start();
            var port = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            tcpListener.Stop();
            return port;
        }

        private static async Task RespondOnceWithoutContentType(HttpListener listener, HttpStatusCode statusCode, byte[] body)
        {
            try
            {
                var context = await listener.GetContextAsync();
                context.Response.StatusCode = (int)statusCode;
                context.Response.ContentLength64 = body.Length;

                await context.Response.OutputStream.WriteAsync(body);
                context.Response.OutputStream.Close();
                context.Response.Close();
            }
            finally
            {
                listener.Stop();
            }
        }
    }
}

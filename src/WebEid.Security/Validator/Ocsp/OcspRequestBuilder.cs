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
/*
 * Copyright 2017 The Netty Project
 * Copyright © 2020-2023 Estonian Information System Authority
 *
 * The Netty Project and The Web eID Project license this file to you under the
 * Apache License, version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.Collections;
    using System.Security.Cryptography;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Ocsp;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Ocsp;

    public class OcspRequestBuilder
    {
        private bool ocspNonceEnabled = true;
        private CertificateID certificateId;

        public byte[] Nonce { get; private set; }

        public OcspRequestBuilder WithCertificateId(CertificateID certificateId)
        {
            this.certificateId = certificateId;
            return this;
        }

        public OcspRequestBuilder EnableOcspNonce(bool enable)
        {
            this.ocspNonceEnabled = enable;
            return this;
        }

        /// <summary>
        /// The returned <see cref="OcspReq"/> is not re-usable/cacheable! It contains a one-time nonce
        /// and responders will reject subsequent requests that have the same nonce value.
        /// </summary>
        /// <returns>An instance of OcspReq object</returns>
        public OcspReq Build()
        {
            ValidateParameters(this.certificateId);

            var generator = new OcspReqGenerator();
            generator.AddRequest(this.certificateId);

            if (this.ocspNonceEnabled)
            {
                this.AddNonce(generator);
            }

            return generator.Generate();
        }

        private static void ValidateParameters(CertificateID certificateId)
        {
            if (certificateId == null)
            {
                throw new ArgumentNullException(nameof(certificateId));
            }
        }

        private void AddNonce(OcspReqGenerator builder)
        {
            this.Nonce = new byte[8];

            using (var rndGenerator = RandomNumberGenerator.Create())
            {
                rndGenerator.GetBytes(this.Nonce);
            }

            IDictionary extensions = new Hashtable
            {
                { OcspObjectIdentifiers.PkixOcspNonce, new X509Extension(false, new DerOctetString(this.Nonce)) }
            };
            builder.SetRequestExtensions(new X509Extensions(extensions));
        }
    }
}

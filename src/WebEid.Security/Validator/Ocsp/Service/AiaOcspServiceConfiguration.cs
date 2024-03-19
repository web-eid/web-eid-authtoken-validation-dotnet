/*
 * Copyright © 2020-2024 Estonian Information System Authority
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
namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    public sealed class AiaOcspServiceConfiguration : IEquatable<AiaOcspServiceConfiguration>
    {
        public AiaOcspServiceConfiguration(List<Uri> nonceDisabledOcspUrls, List<X509Certificate2> trustedCaCertificates)
        {
            this.NonceDisabledOcspUrls =
                nonceDisabledOcspUrls ?? throw new ArgumentNullException(nameof(nonceDisabledOcspUrls));
            this.TrustedCaCertificates =
                trustedCaCertificates ?? throw new ArgumentNullException(nameof(trustedCaCertificates));
        }

        public List<Uri> NonceDisabledOcspUrls { get; }
        public List<X509Certificate2> TrustedCaCertificates { get; }
        public bool Equals(AiaOcspServiceConfiguration other)
        {
            if (other is null)
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return Enumerable.SequenceEqual(this.NonceDisabledOcspUrls, other.NonceDisabledOcspUrls) &&
                   Enumerable.SequenceEqual(this.TrustedCaCertificates, other.TrustedCaCertificates);
        }

        public override bool Equals(object obj) => ReferenceEquals(this, obj) || obj is AiaOcspServiceConfiguration other && Equals(other);

        public override int GetHashCode()
        {
            unchecked
            {
                return ((this.NonceDisabledOcspUrls != null ? this.NonceDisabledOcspUrls.GetHashCode() : 0) * 397) ^
                       (this.TrustedCaCertificates != null ? this.TrustedCaCertificates.GetHashCode() : 0);
            }
        }

        public static bool operator ==(AiaOcspServiceConfiguration left, AiaOcspServiceConfiguration right) => Equals(left, right);

        public static bool operator !=(AiaOcspServiceConfiguration left, AiaOcspServiceConfiguration right) => !Equals(left, right);
    }
}

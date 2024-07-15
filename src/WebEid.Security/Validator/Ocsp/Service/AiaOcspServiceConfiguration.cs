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

    /// <summary>
    /// Represents the configuration for an AIA (Authority Information Access) OCSP service.
    /// </summary>
    public sealed class AiaOcspServiceConfiguration : IEquatable<AiaOcspServiceConfiguration>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AiaOcspServiceConfiguration"/> class.
        /// </summary>
        /// <param name="nonceDisabledOcspUrls">List of OCSP responder URLs where nonce is disabled.</param>
        /// <param name="trustedCaCertificates">List of trusted CA certificates.</param>
        public AiaOcspServiceConfiguration(List<Uri> nonceDisabledOcspUrls, List<X509Certificate2> trustedCaCertificates)
        {
            this.NonceDisabledOcspUrls =
                nonceDisabledOcspUrls ?? throw new ArgumentNullException(nameof(nonceDisabledOcspUrls));
            this.TrustedCaCertificates =
                trustedCaCertificates ?? throw new ArgumentNullException(nameof(trustedCaCertificates));
        }

        /// <summary>
        /// Gets the list of OCSP responder URLs where nonce is disabled.
        /// </summary>
        public List<Uri> NonceDisabledOcspUrls { get; }

        /// <summary>
        /// Gets the list of trusted CA certificates.
        /// </summary>
        public List<X509Certificate2> TrustedCaCertificates { get; }

        /// <summary>
        /// Determines whether the current instance is equal to another <see cref="AiaOcspServiceConfiguration"/>.
        /// </summary>
        /// <param name="other">The other <see cref="AiaOcspServiceConfiguration"/> to compare.</param>
        /// <returns>True if equal, false otherwise.</returns>
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

        /// <inheritdoc/>
        public override bool Equals(object obj) => ReferenceEquals(this, obj) || obj is AiaOcspServiceConfiguration other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            unchecked
            {
                return ((this.NonceDisabledOcspUrls != null ? this.NonceDisabledOcspUrls.GetHashCode() : 0) * 397) ^
                       (this.TrustedCaCertificates != null ? this.TrustedCaCertificates.GetHashCode() : 0);
            }
        }

        /// <summary>
        /// Determines whether two <see cref="AiaOcspServiceConfiguration"/> instances are equal.
        /// </summary>
        public static bool operator ==(AiaOcspServiceConfiguration left, AiaOcspServiceConfiguration right) => Equals(left, right);

        /// <summary>
        /// Determines whether two <see cref="AiaOcspServiceConfiguration"/> instances are not equal.
        /// </summary>
        public static bool operator !=(AiaOcspServiceConfiguration left, AiaOcspServiceConfiguration right) => !Equals(left, right);
    }
}

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Represents the configuration for an AIA (Authority Information Access) OCSP service.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="AiaOcspServiceConfiguration"/> class.
    /// </remarks>
    /// <param name="nonceDisabledOcspUrls">List of OCSP responder URLs where nonce is disabled.</param>
    /// <param name="trustedCaCertificates">List of trusted CA certificates.</param>
    /// <param name="responderIssuerMatchingPolicy">How the issuer authorizing an AIA OCSP responder is matched
    /// against the subject certificate's issuer.</param>
    /// <param name="revocationUrlRetrievalTimeout">Maximum time spent retrieving OCSP or CRL data while checking
    /// intermediate certificate revocation.</param>
    public sealed class AiaOcspServiceConfiguration(List<Uri> nonceDisabledOcspUrls,
        List<X509Certificate2> trustedCaCertificates,
        ResponderIssuerMatchingPolicy responderIssuerMatchingPolicy = ResponderIssuerMatchingPolicy.ExactCertificate,
        TimeSpan? revocationUrlRetrievalTimeout = null) : IEquatable<AiaOcspServiceConfiguration>
    {

        /// <summary>
        /// Gets the list of OCSP responder URLs where nonce is disabled.
        /// </summary>
        public List<Uri> NonceDisabledOcspUrls { get; } =
                nonceDisabledOcspUrls ?? throw new ArgumentNullException(nameof(nonceDisabledOcspUrls));

        /// <summary>
        /// Gets the list of trusted CA certificates.
        /// </summary>
        public List<X509Certificate2> TrustedCaCertificates { get; } =
                trustedCaCertificates ?? throw new ArgumentNullException(nameof(trustedCaCertificates));

        /// <summary>
        /// Gets the policy for matching the issuer authorizing an AIA OCSP responder against the subject
        /// certificate's issuer.
        /// </summary>
        public ResponderIssuerMatchingPolicy ResponderIssuerMatchingPolicy { get; } = responderIssuerMatchingPolicy;

        /// <summary>
        /// Gets the maximum time spent retrieving OCSP or CRL data while checking intermediate certificate
        /// revocation.
        /// </summary>
        public TimeSpan RevocationUrlRetrievalTimeout { get; } =
            RequirePositiveTimeout(revocationUrlRetrievalTimeout ?? TimeSpan.FromSeconds(5));

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

            return Enumerable.SequenceEqual(NonceDisabledOcspUrls, other.NonceDisabledOcspUrls) &&
                   Enumerable.SequenceEqual(TrustedCaCertificates, other.TrustedCaCertificates) &&
                   ResponderIssuerMatchingPolicy == other.ResponderIssuerMatchingPolicy &&
                   RevocationUrlRetrievalTimeout == other.RevocationUrlRetrievalTimeout;
        }

        /// <inheritdoc/>
        public override bool Equals(object obj) => ReferenceEquals(this, obj) || (obj is AiaOcspServiceConfiguration other && Equals(other));

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = NonceDisabledOcspUrls != null ? NonceDisabledOcspUrls.GetHashCode() : 0;
                hashCode = (hashCode * 397) ^ (TrustedCaCertificates != null ? TrustedCaCertificates.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ ResponderIssuerMatchingPolicy.GetHashCode();
                return (hashCode * 397) ^ RevocationUrlRetrievalTimeout.GetHashCode();
            }
        }

        private static TimeSpan RequirePositiveTimeout(TimeSpan revocationUrlRetrievalTimeout) =>
            revocationUrlRetrievalTimeout > TimeSpan.Zero
                ? revocationUrlRetrievalTimeout
                : throw new ArgumentOutOfRangeException(nameof(revocationUrlRetrievalTimeout),
                    "Intermediate certificate revocation URL retrieval timeout must be greater than zero");

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

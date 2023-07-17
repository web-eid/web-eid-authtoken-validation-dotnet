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

namespace WebEid.Security.Validator
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using Microsoft.IdentityModel.Tokens;

    internal static class SignatureAlgorithm
    {
        private static readonly ICollection<string> SupportedSigningAlgorithms = new Collection<string>
        {
            SecurityAlgorithms.None,
            SecurityAlgorithms.EcdsaSha256,
            SecurityAlgorithms.EcdsaSha384,
            SecurityAlgorithms.EcdsaSha512,
            SecurityAlgorithms.HmacSha256,
            SecurityAlgorithms.HmacSha384,
            SecurityAlgorithms.HmacSha512,
            SecurityAlgorithms.RsaSha256,
            SecurityAlgorithms.RsaSha384,
            SecurityAlgorithms.RsaSha512,
            SecurityAlgorithms.RsaSsaPssSha256,
            SecurityAlgorithms.RsaSsaPssSha384,
            SecurityAlgorithms.RsaSsaPssSha512
        };

        public static void ValidateIfSupported(string name)
        {
            if (string.IsNullOrWhiteSpace(name) ||
                name.Equals(SecurityAlgorithms.None, StringComparison.InvariantCultureIgnoreCase) ||
                !SupportedSigningAlgorithms.Any(alg => alg.Equals(name, StringComparison.InvariantCultureIgnoreCase)))
            {
                throw new NotSupportedException($"Unsupported signature algorithm '{name}'");
            }
        }
    }
}

namespace WebEid.Security.Validator
{
    using System;
    using System.Security;

    internal static class SignatureAlgorithmExtensions
    {
        /// <summary>
        /// Looks up and returns the corresponding <see cref="SignatureAlgorithm"/> enum based on a
        /// case-<em>insensitive</em> name comparison.
        /// </summary>
        /// <param name="name">The case-insensitive name of the <see cref="SignatureAlgorithm"/> enum value to return</param>
        /// <returns>the corresponding <see cref="SignatureAlgorithm"/> enum value based on a case-<em>insensitive</em> name comparison</returns>
        public static SignatureAlgorithm ForName(this string name)
        {
            Enum.TryParse(name, true, out SignatureAlgorithm value);
            if (value == SignatureAlgorithm.None)
            {
                throw new SecurityException($"Unsupported signature algorithm '{value}'");
            }

            return value;
        }
    }
}

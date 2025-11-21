// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Validator.VersionValidators
{
    using System.Globalization;
    using System.Text.RegularExpressions;

    /// <summary>
    /// Utility for matching Web eID authentication token format version strings of the form
    /// <c>web-eid:&lt;major&gt;[.&lt;minor&gt;]</c>, e.g. <c>web-eid:1</c> or <c>web-eid:1.1</c>.
    /// </summary>
    internal static partial class AuthTokenVersion
    {
        // Matches 'web-eid:<major>' with an optional canonical '.<minor>', where both numbers have no leading
        // zeros ('0' or '[1-9]\d*') and are at most 9 digits so that they always fit in an int. Non-canonical
        // spellings such as 'web-eid:1.00' or 'web-eid:01' are rejected so that ambiguous version numbers cannot
        // bypass the more specific validators.
        [GeneratedRegex(@"^web-eid:(0|[1-9]\d{0,8})(?:\.(0|[1-9]\d{0,8}))?$")]
        private static partial Regex TokenFormatRegex();

        /// <summary>
        /// Returns whether the given token format has exactly the required major version and a minor version that
        /// is greater than or equal to the required minor version. A missing minor version is treated as 0.
        /// Backwards-compatible minor version changes are supported within the same major version, while an
        /// incompatible major version change is not.
        /// </summary>
        internal static bool Supports(string format, int requiredExactMajorVersion, int requiredMinimalMinorVersion)
        {
            var version = Parse(format);
            return version.HasValue &&
                version.Value.Major == requiredExactMajorVersion &&
                version.Value.Minor >= requiredMinimalMinorVersion;
        }

        /// <summary>
        /// Returns whether the given token format has exactly the required major version and exactly the required
        /// minor version. A missing minor version is treated as 0.
        /// </summary>
        internal static bool SupportsExactly(string format, int requiredExactMajorVersion, int requiredExactMinorVersion)
        {
            var version = Parse(format);
            return version.HasValue &&
                version.Value.Major == requiredExactMajorVersion &&
                version.Value.Minor == requiredExactMinorVersion;
        }

        private static (int Major, int Minor)? Parse(string format)
        {
            if (format == null)
            {
                return null;
            }

            var match = TokenFormatRegex().Match(format);
            if (!match.Success)
            {
                return null;
            }

            var major = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
            var minor = match.Groups[2].Success
                ? int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture)
                : 0;

            return (major, minor);
        }
    }
}

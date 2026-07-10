// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Util
{
    /// <summary>
    /// Provides constants for subject certificate policies related to the Estonian eID system.
    /// </summary>
    public static class SubjectCertificatePolicies
    {
        /// <summary>
        /// The base OID prefix for the Estonian eID system's mobile ID policy.
        /// </summary>
        private const string EsteidSk2015MobileIdPolicyPrefix = "1.3.6.1.4.1.10015.1.3";

        /// <summary>
        /// The OID for the Estonian eID system's mobile ID policy.
        /// </summary>
        public const string EsteidSk2015MobileIdPolicy = EsteidSk2015MobileIdPolicyPrefix;

        /// <summary>
        /// The OID for the Estonian eID system's mobile ID policy version 1.
        /// </summary>
        public const string EsteidSk2015MobileIdPolicyV1 = EsteidSk2015MobileIdPolicyPrefix + ".1";

        /// <summary>
        /// The OID for the Estonian eID system's mobile ID policy version 2.
        /// </summary>
        public const string EsteidSk2015MobileIdPolicyV2 = EsteidSk2015MobileIdPolicyPrefix + ".2";

        /// <summary>
        /// The OID for the Estonian eID system's mobile ID policy version 3.
        /// </summary>
        public const string EsteidSk2015MobileIdPolicyV3 = EsteidSk2015MobileIdPolicyPrefix + ".3";
    }
}

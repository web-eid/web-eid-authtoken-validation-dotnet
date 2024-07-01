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

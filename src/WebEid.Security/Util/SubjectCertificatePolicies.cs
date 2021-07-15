namespace WebEid.Security.Util
{
    public static class SubjectCertificatePolicies
    {
        private const string EsteidSk2015MobileIdPolicyPrefix = "1.3.6.1.4.1.10015.1.3";

        public const string EsteidSk2015MobileIdPolicy = EsteidSk2015MobileIdPolicyPrefix;

        public const string EsteidSk2015MobileIdPolicyV1 = EsteidSk2015MobileIdPolicyPrefix + ".1";

        public const string EsteidSk2015MobileIdPolicyV2 = EsteidSk2015MobileIdPolicyPrefix + ".2";

        public const string EsteidSk2015MobileIdPolicyV3 = EsteidSk2015MobileIdPolicyPrefix + ".3";
    }
}

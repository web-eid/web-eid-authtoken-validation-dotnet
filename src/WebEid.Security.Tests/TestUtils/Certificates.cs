namespace WebEid.Security.Tests.TestUtils
{
    using System.Reflection;
    using System.Security.Cryptography.X509Certificates;
    using WebEid.Security.Util;

    internal static class Certificates
    {
        public static readonly ResourceReader ResourceReader = new(Assembly.GetCallingAssembly(), "WebEid.Security.Tests.Resources");
        public static readonly CertificateLoader CertificateLoader = new(ResourceReader);

        private const string JaakKristjanEsteid2018Cert = "MIIEAzCCA2WgAwIBAgIQOWkBWXNDJm1byFd3XsWkvjAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MTAxODA5NTA0N1oXDTIzMTAxNzIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR5k1lXzvSeI9O/1s1pZvjhEW8nItJoG0EBFxmLEY6S7ki1vF2Q3TEDx6dNztI1Xtx96cs8r4zYTwdiQoDg7k3diUuR9nTWGxQEMO1FDo4Y9fAmiPGWT++GuOVoZQY3XxijggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOQsvTQJEBVMMSmhyZX5bibYJubAMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgH1UsmMdtLZti51Fq2QR4wUkAwpsnhsBV2HQqUXFYBJ7EXnLCkaXjdZKkHpABfM0QEx7UUhaI4i53jiJ7E1Y7WOAAJBDX4z61pniHJapI1bkMIiJQ/ti7ha8fdJSMSpAds5CyHIyHkQzWlVy86f9mA7Eu3oRO/1q+eFUzDbNN3Vvy7gQWQ=";
        private const string MariliisEsteid2015Cert = "MIIFwjCCA6qgAwIBAgIQY+LgQ6n0BURZ048wIEiYHjANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNURUlELVNLIDIwMTUwHhcNMTcxMDAzMTMyMjU2WhcNMjIxMDAyMjA1OTU5WjCBnjELMAkGA1UEBhMCRUUxDzANBgNVBAoMBkVTVEVJRDEaMBgGA1UECwwRZGlnaXRhbCBzaWduYXR1cmUxJjAkBgNVBAMMHU3DhE5OSUssTUFSSS1MSUlTLDYxNzEwMDMwMTYzMRAwDgYDVQQEDAdNw4ROTklLMRIwEAYDVQQqDAlNQVJJLUxJSVMxFDASBgNVBAUTCzYxNzEwMDMwMTYzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+nNdtmZ2Ve3XXtjBEGwpvVrDIg7slPfLlyHbCBFMXevfqW5KsXIOy6E2A+Yof+/cqRlY4IhsX2Ka9SsJSo8/EekasFasLFPw9ZBE3MG0nn5zaatg45VSjnPinMmrzFzxo4IB2jCCAdYwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBkAwgYsGA1UdIASBgzCBgDBzBgkrBgEEAc4fAwEwZjAvBggrBgEFBQcCARYjaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9vcml1bS9DUFMwMwYIKwYBBQUHAgIwJwwlQWludWx0IHRlc3RpbWlzZWtzLiBPbmx5IGZvciB0ZXN0aW5nLjAJBgcEAIvsQAECMB0GA1UdDgQWBBTiw6M0uow+u6sfhgJAWCSvtkB/ejAiBggrBgEFBQcBAwQWMBQwCAYGBACORgEBMAgGBgQAjkYBBDAfBgNVHSMEGDAWgBRJwPJEOWXVm0Y7DThgg7HWLSiGpjCBgwYIKwYBBQUHAQEEdzB1MCwGCCsGAQUFBzABhiBodHRwOi8vYWlhLmRlbW8uc2suZWUvZXN0ZWlkMjAxNTBFBggrBgEFBQcwAoY5aHR0cHM6Ly9zay5lZS91cGxvYWQvZmlsZXMvVEVTVF9vZl9FU1RFSUQtU0tfMjAxNS5kZXIuY3J0MEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly93d3cuc2suZWUvY3Jscy9lc3RlaWQvdGVzdF9lc3RlaWQyMDE1LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAEWBdwmzo/yRncJXKvrE+A1G6yQaBNarKectI5uk18BewYEA4QkhmIwOCwD83jBDB9JF+kuODMHsnvz2mfhwaB/uJIPwfBDQ5JCMBdHPsxLN9nzW/UUzqv2UDMwFkibHCcfV5lTBcmOd7FagUHTUm+8gRlWbDiVl5yPochdJgGYPV+fs/jc5ttHaBvBon0z9LbI4qi0VXdRmV0iogErh8JF5yfGkbfGRaMkWkNYQtQ68i/hPe6MaUxL2/MMt4YTyXtVghmc3ZKZIyp4j0+jlK4vL+d4gaE+TvoQvh6HrmP145FqlMDurATWdB069+hdDLO5fI6AYkc79D5XPKwQ/f1MBufLtBYtOJmtpLT+tdBt/EqOEIO/0FeHcXZlFioNMuxBBeTE/QcDtJ2jxTcg8jNOoepS0wjuxBon9iI1710SR53DLGSWdL52lPoBFacnyPQI1htXVUkJ8icMQKYe3BLt1Ha2cvsA4n4IpjqVROX4mzoPL1hg/aJlD+W2uI2ppYRUNY5FX7C0R+AYzMpOahQ7STQfUxtEnKW98e1I33LWwpjJW9q4htsZeXs4Zatf9ssfUW0VA49tnI28kkN2D8aw1NgWfzVlnJKkEj0qa3ewLZK577j8MexAetT/7leH6mqewr9ewC/tKbYjhufieXx6RPcRC4OZsxtii7ih8TqRg=";

        private static X509Certificate testEsteid2018Ca;
        private static X509Certificate testEsteid2015Ca;

        private static X509Certificate2 jaakKristjanEsteid2018Cert;
        private static X509Certificate mariliisEsteid2015Cert;
        private static X509Certificate testSkOcspResponder2020;

        private static void LoadCertificates()
        {
            var certificates = CertificateLoader.LoadCertificatesFromResources(
                "TEST_of_ESTEID-SK_2015.cer",
                "TEST_of_ESTEID2018.cer",
                "TEST_of_ESTEID-SK_2018_AIA_OCSP_RESPONDER_202304.cer");
            testEsteid2015Ca = certificates[0];
            testEsteid2018Ca = certificates[1];
            testSkOcspResponder2020 = certificates[2];
        }

        public static X509Certificate GetTestEsteid2018Ca()
        {
            if (testEsteid2018Ca == null)
            {
                LoadCertificates();
            }
            return testEsteid2018Ca;
        }

        public static X509Certificate GetTestEsteid2015Ca()
        {
            if (testEsteid2015Ca == null)
            {
                LoadCertificates();
            }
            return testEsteid2015Ca;
        }

        public static X509Certificate GetTestSkOcspResponder2023()
        {
            if (testSkOcspResponder2020 == null)
            {
                LoadCertificates();
            }
            return testSkOcspResponder2020;
        }

        public static X509Certificate2 GetJaakKristjanEsteid2018Cert()
        {
            if (jaakKristjanEsteid2018Cert == null)
            {
                jaakKristjanEsteid2018Cert = CertificateLoader.LoadCertificateFromBase64String(JaakKristjanEsteid2018Cert);
            }
            return jaakKristjanEsteid2018Cert;
        }

        public static X509Certificate GetMariliisEsteid2015Cert()
        {
            if (mariliisEsteid2015Cert == null)
            {
                mariliisEsteid2015Cert = CertificateLoader.LoadCertificateFromBase64String(MariliisEsteid2015Cert);
            }
            return mariliisEsteid2015Cert;
        }
    }
}

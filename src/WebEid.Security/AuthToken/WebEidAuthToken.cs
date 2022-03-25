namespace WebEid.Security.AuthToken
{
    public class WebEidAuthToken
    {
        public string Algorithm { get; set; }
        public string Format { get; set; }
        public string Signature { get; set; }
        public string UnverifiedCertificate { get; set; }
    }
}

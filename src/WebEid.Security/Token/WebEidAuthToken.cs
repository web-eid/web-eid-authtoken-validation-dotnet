namespace WebEid.Security.Token
{
    public class WebEidAuthToken
    {
        public string Algorithm { get; set; }
        public string Certificate { get; set; }
        public string IssuerApp { get; set; }
        public string Signature { get; set; }
        public string Version { get; set; }
    }
}

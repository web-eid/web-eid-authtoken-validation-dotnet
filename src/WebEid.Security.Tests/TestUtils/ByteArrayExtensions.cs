namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using System.Text;

    internal static class ByteArrayExtensions
    {
        public static string ToUtf8String(this byte[] bytes)
        {
            if (bytes == null)
            {
                return null;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }

    internal static class StringExtensions
    {
        public static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding  
            output = output.Replace('_', '/'); // 63rd char of encoding  
            switch (output.Length % 4) // Pad with trailing '='s  
            {
                case 0:
                    break; // No pad chars in this case  
                case 2:
                    output += "==";
                    break; // Two pad chars  
                case 3:
                    output += "=";
                    break; // One pad char  
                default:
                    throw new ArgumentException("Illegal base64url string!");
            }

            return Convert.FromBase64String(output);
        }
    }
}

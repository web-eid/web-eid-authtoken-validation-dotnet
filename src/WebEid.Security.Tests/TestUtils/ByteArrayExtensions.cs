/*
 * Copyright © 2020-2023 Estonian Information System Authority
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

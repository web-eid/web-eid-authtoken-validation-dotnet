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
namespace WebEid.Security.Util
{
    using System;
    using System.IO;
    using System.Reflection;

    public class ResourceReader
    {
        private readonly Assembly assembly;
        private readonly string assemblyNamespace;

        public ResourceReader(Assembly assembly, string assemblyNamespace)
        {
            this.assembly = assembly;
            this.assemblyNamespace = assemblyNamespace;
            if (!this.assemblyNamespace.EndsWith(".", StringComparison.InvariantCulture))
            {
                this.assemblyNamespace += ".";
            }
        }

        public byte[] ReadFromResource(string filename)
        {
            using var stream = this.GetStream(filename);
            if (stream == null)
            {
                throw new ArgumentException($"Unable to find resource: {this.assemblyNamespace + filename}");
            }
            return stream.ToByteArray();
        }

        private Stream GetStream(string filename) =>
            this.assembly.GetManifestResourceStream(this.assemblyNamespace + filename);
    }
}

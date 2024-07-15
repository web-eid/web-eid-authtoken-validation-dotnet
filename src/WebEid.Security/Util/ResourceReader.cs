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
    using System;
    using System.IO;
    using System.Reflection;

    /// <summary>
    /// Provides methods for reading embedded resources from an assembly.
    /// </summary>
    public class ResourceReader
    {
        private readonly Assembly assembly;
        private readonly string assemblyNamespace;

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceReader"/> class.
        /// </summary>
        /// <param name="assembly">The assembly containing the embedded resources.</param>
        /// <param name="assemblyNamespace">The base namespace for the embedded resources.</param>
        public ResourceReader(Assembly assembly, string assemblyNamespace)
        {
            this.assembly = assembly;
            this.assemblyNamespace = assemblyNamespace;
            if (!this.assemblyNamespace.EndsWith(".", StringComparison.InvariantCulture))
            {
                this.assemblyNamespace += ".";
            }
        }

        /// <summary>
        /// Reads the content of an embedded resource.
        /// </summary>
        /// <param name="filename">The name of the embedded resource.</param>
        /// <returns>The content of the embedded resource as a byte array.</returns>
        /// <exception cref="ArgumentException">Thrown when the resource is not found.</exception>
        public byte[] ReadFromResource(string filename)
        {
            using var stream = this.GetStream(filename) ?? throw new ArgumentException($"Unable to find resource: {this.assemblyNamespace + filename}");
            return stream.ToByteArray();
        }

        private Stream GetStream(string filename) =>
            this.assembly.GetManifestResourceStream(this.assemblyNamespace + filename);
    }
}

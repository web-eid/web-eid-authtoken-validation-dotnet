// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
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

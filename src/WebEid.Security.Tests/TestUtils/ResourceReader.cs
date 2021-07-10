namespace WebEID.Security.Tests.TestUtils
{
    using System;
    using System.IO;
    using System.Reflection;

    internal class ResourceReader
    {
        private readonly Assembly assembly;

        private readonly string assemblyNamespace;

        private static readonly ResourceReader Reader = new ResourceReader("WebEID.Security.Tests.Resources");

        public static byte[] ReadFromResource(string filename)
        {
            return Reader.GetBytes(filename);
        }

        public ResourceReader(string assemblyNamespace)
        {
            this.assemblyNamespace = assemblyNamespace;
            if (!this.assemblyNamespace.EndsWith(".", StringComparison.InvariantCulture))
            {
                this.assemblyNamespace += ".";
            }

            this.assembly = Assembly.GetCallingAssembly();
        }

        private Stream GetStream(string filename)
        {
            return this.assembly.GetManifestResourceStream(this.assemblyNamespace + filename);
        }

        public byte[] GetBytes(string filename)
        {
            using (var stream = this.GetStream(filename))
            {
                if (stream == null)
                {
                    throw new ArgumentException($"Unable to find resource: {this.assemblyNamespace + filename}");
                }

                return stream.ToByteArray();
            }
        }
    }
}

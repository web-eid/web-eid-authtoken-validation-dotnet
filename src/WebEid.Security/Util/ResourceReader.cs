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

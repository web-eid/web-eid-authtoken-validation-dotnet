namespace WebEID.Security.Tests.TestUtils
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Reflection;

    public class ResourceReader
    {
        private readonly Assembly assembly;

        private readonly string assemblyNamespace;

        public ResourceReader(string assemblyNamespace)
        {
            this.assemblyNamespace = assemblyNamespace;
            if (!this.assemblyNamespace.EndsWith(".", StringComparison.InvariantCulture))
            {
                this.assemblyNamespace += ".";
            }

            this.assembly = Assembly.GetCallingAssembly();
        }

        public Stream GetStream(string filename)
        {
            return this.assembly.GetManifestResourceStream(this.assemblyNamespace + filename);
        }

        public IEnumerable<string> GetResourceNames()
        {
            return from name in this.assembly.GetManifestResourceNames()
                select name.Replace(this.assemblyNamespace, string.Empty);
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

    public static class ResourceHelper
    {
        private static readonly ResourceReader Helper = new ResourceReader("Rik.Pris.Utilities.Tests.Resources");

        public static Stream GetStream(string filename)
        {
            return Helper.GetStream(filename);
        }

        public static IEnumerable<string> GetResourceNames()
        {
            return Helper.GetResourceNames();
        }

        public static byte[] GetBytes(string filename)
        {
            return Helper.GetBytes(filename);
        }
    }
}

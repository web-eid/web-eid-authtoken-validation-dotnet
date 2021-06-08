namespace WebEID.Security.Util
{
    using System;

    public static class OcspUrls
    {
#pragma warning disable S1075 // URIs should not be hardcoded
        public static readonly Uri Esteid2015 = new Uri("http://aia.sk.ee/esteid2015"); //NOSONAR
#pragma warning restore S1075 // URIs should not be hardcoded
    }
}

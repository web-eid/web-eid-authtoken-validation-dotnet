namespace WebEid.Security.Tests.TestUtils
{
    using System;

    internal static class DateTimeExtensions
    {
        internal static DateTime TrimMilliseconds(this DateTime dt)
        {
            return dt.AddTicks(-dt.Ticks % TimeSpan.TicksPerSecond);
        }
    }
}

namespace WebEid.Security.Util
{
    using System;

    public static class TimespanExtensions
    {
        public static bool IsNegativeOrZero(this TimeSpan timeSpan) =>
            timeSpan.CompareTo(TimeSpan.Zero) <= 0;
    }
}

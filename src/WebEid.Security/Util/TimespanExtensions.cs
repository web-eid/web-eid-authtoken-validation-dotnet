namespace WebEID.Security.Util
{
    using System;

    public static class TimespanExtensions
    {
        public static bool IsNegativeOrZero(this TimeSpan timeSpan)
        {
            return timeSpan.CompareTo(TimeSpan.Zero) <= 0;
        }
    }
}

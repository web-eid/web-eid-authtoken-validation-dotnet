namespace WebEid.Security.Util
{
    using System;

    /// <summary>
    /// Used for getting DateTime.UtcNow(), time is changeable for unit testing.
    /// Based on https://stackoverflow.com/a/40299607 and https://stackoverflow.com/a/9911500.
    /// </summary>
    public sealed class DateTimeProvider : IDisposable
    {
        [ThreadStatic]
        private static DateTime? overridenUtcNow;

        /// <summary>
        /// Normally this is a pass-through to DateTime.UtcNow, but it can be overridden
        /// with OverrideUtcNow() for testing or debugging.
        /// </summary>
        public static DateTime UtcNow => overridenUtcNow ?? DateTime.UtcNow;

        /// <summary>Set the time to return when DateTimeProvider.UtcNow() is called.</summary>
        public static DateTimeProvider OverrideUtcNow(DateTime actualDateTime)
        {
            overridenUtcNow = actualDateTime;
            return new DateTimeProvider();
        }

#pragma warning disable S2696 // Remove this set, which updates a 'static' field from an instance method
        public void Dispose() => overridenUtcNow = null; // NOSONAR
#pragma warning restore S2696 // Remove this set, which updates a 'static' field from an instance method
    }
}

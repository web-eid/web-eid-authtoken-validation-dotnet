// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Util
{
    using System;

    /// <summary>
    /// Provides functionality for getting DateTime.UtcNow(), with the ability to override the time for unit testing.
    /// Based on https://stackoverflow.com/a/40299607 and https://stackoverflow.com/a/9911500.
    /// </summary>
    public sealed class DateTimeProvider : IDisposable
    {
        private static DateTime? overridenUtcNow;

        /// <summary>
        /// Normally this is a pass-through to DateTime.UtcNow, but it can be overridden
        /// with OverrideUtcNow() for testing or debugging.
        /// </summary>
        public static DateTime UtcNow => overridenUtcNow ?? DateTime.UtcNow;

        /// <summary>
        /// Sets the time to return when DateTimeProvider.UtcNow() is called.
        /// </summary>
        /// <param name="actualDateTime">The actual DateTime value to override UtcNow.</param>
        /// <returns>An instance of DateTimeProvider with the overridden time.</returns>
        public static DateTimeProvider OverrideUtcNow(DateTime actualDateTime)
        {
            overridenUtcNow = actualDateTime;
            return new DateTimeProvider();
        }

        /// <summary>
        /// Disposes the overridden time, reverting to the default behavior of DateTime.UtcNow.
        /// </summary>
        public void Dispose() => overridenUtcNow = null;
    }
}

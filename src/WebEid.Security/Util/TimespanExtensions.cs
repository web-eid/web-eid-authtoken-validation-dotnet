// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Util
{
    using System;

    /// <summary>
    /// Provides extension methods for <see cref="TimeSpan"/>.
    /// </summary>
    public static class TimespanExtensions
    {
        /// <summary>
        /// Determines whether the specified <see cref="TimeSpan"/> is negative or zero.
        /// </summary>
        /// <param name="timeSpan">The <see cref="TimeSpan"/> to check.</param>
        /// <returns>True if the <see cref="TimeSpan"/> is negative or zero; otherwise, false.</returns>
        public static bool IsNegativeOrZero(this TimeSpan timeSpan) =>
            timeSpan.CompareTo(TimeSpan.Zero) <= 0;
    }
}

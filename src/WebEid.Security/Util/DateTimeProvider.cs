/*
 * Copyright © 2020-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
namespace WebEid.Security.Util
{
    using System;

    /// <summary>
    /// Used for getting DateTime.UtcNow(), time is changeable for unit testing.
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

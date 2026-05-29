// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using Org.BouncyCastle.Asn1;

    internal static class DateTimeExtensions
    {
        internal static DateTime TrimMilliseconds(this DateTime dt)
        {
            return dt.AddTicks(-dt.Ticks % TimeSpan.TicksPerSecond);
        }

        internal static DerGeneralizedTime ToDerGenTime(this DateTime dateTime) => new(dateTime);
    }
}

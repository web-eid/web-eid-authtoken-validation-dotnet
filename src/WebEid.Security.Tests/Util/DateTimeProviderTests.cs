namespace WebEid.Security.Tests.Util
{
    using System;
    using NUnit.Framework;
    using TestUtils;
    using WebEid.Security.Util;

    [TestFixture]
    public class DateTimeProviderTests
    {
        [Test]
        public void DateTimeProviderOverrideAndResetUtcNow()
        {
            using (DateTimeProvider.OverrideUtcNow(new DateTime(2000, 1, 1)))
            {
                Assert.That(DateTimeProvider.UtcNow, Is.EqualTo(new DateTime(2000, 1, 1)));
            }

            Assert.That(DateTimeProvider.UtcNow.TrimMilliseconds(), Is.EqualTo(DateTime.UtcNow.TrimMilliseconds()));
        }
    }
}

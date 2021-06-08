namespace WebEID.Security.Tests.TestUtils
{
    using System;
    using NUnit.Framework;

    internal static class TestingExtensions
    {
        public static void WithMessage(this Exception exception, string expectedMessage)
        {
            Assert.AreEqual(expectedMessage, exception.Message);
        }
    }
}

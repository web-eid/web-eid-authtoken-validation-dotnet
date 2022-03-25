namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using NUnit.Framework;

    internal static class TestingExtensions
    {
        public static void WithMessage(this Exception exception, string expectedMessage) =>
            Assert.AreEqual(expectedMessage, exception.Message);

        public static void HasMessageStartingWith(this Exception exception, string expectedMessage) =>
            Assert.True(exception.Message.StartsWith(expectedMessage, StringComparison.InvariantCulture), $"Exception message: '{exception.Message}' does not start with: '{expectedMessage}'");

        public static void HasMessage(this Exception exception, string expectedMessage) =>
            Assert.True(exception.Message.Contains(expectedMessage, StringComparison.InvariantCulture), $"Exception message: '{exception.Message}' does not start with: '{expectedMessage}'");

        public static Exception IsInstanceOf<T>(this Exception exception) where T : Exception
        {
            Assert.True(exception.GetType() == typeof(T),
                $"Exception of type {exception.GetType()} is not equal to expected type: {typeof(T)}");
            return exception;
        }
    }
}

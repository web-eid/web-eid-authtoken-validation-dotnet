/*
 * Copyright © 2020-2023 Estonian Information System Authority
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

namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using Microsoft.QualityTools.Testing.Fakes;
    using NUnit.Framework;

    public abstract class AbstractTestWithMockedDate : AbstractTestWithCache
    {
        private IDisposable context;

        [SetUp]
        protected override void SetUp()
        {
            base.SetUp();
            this.context = ShimsContext.Create();
            // Authentication token is valid until 2020-04-14
            System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 11, 0, 0, 0, DateTimeKind.Utc);
        }

        [TearDown]
        protected override void TearDown()
        {
            base.TearDown();
            this.context.Dispose();
        }
    }
}

namespace WebEid.Security.Tests.TestUtils
{
    using NUnit.Framework;

    public abstract class AbstractTestWithMockedDateAndCorrectNonce : AbstractTestWithMockedDate
    {
        [SetUp]
        protected override void SetUp()
        {
            base.SetUp();
            this.PutCorrectNonceToCache();
        }
    }
}

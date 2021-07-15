namespace WebEid.Security.Tests.TestUtils
{
    using NUnit.Framework;

    public abstract class AbstractTestWithValidatorAndCorrectNonce : AbstractTestWithValidator
    {
        [SetUp]
        protected override void SetUp()
        {
            base.SetUp(); 
            this.PutCorrectNonceToCache();
        }
    }
}

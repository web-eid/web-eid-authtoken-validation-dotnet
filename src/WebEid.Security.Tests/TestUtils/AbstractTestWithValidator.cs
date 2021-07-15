namespace WebEid.Security.Tests.TestUtils
{
    using NUnit.Framework;
    using Security.Validator;

    public abstract class AbstractTestWithValidator : AbstractTestWithCache
    {
        protected IAuthTokenValidator Validator { get; set; }

        [SetUp]
        protected override void SetUp()
        {
            base.SetUp();
            this.Validator = AuthTokenValidators.GetAuthTokenValidator(this.Cache);
        }
    }
}

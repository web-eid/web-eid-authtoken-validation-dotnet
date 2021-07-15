namespace WebEid.Security.Validator.Validators
{
    using System.Threading.Tasks;

    internal interface IValidator
    {
        Task Validate(AuthTokenValidatorData actualTokenData);
    }
}

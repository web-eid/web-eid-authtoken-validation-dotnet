namespace WebEID.Security.Validator.Validators
{
    public interface IValidator
    {
        void Validate(AuthTokenValidatorData actualTokenData);
    }
}

namespace WebEid.Security.Validator.Validators
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    internal sealed class ValidatorBatch
    {
        private readonly List<IValidator> validatorList;

        public static ValidatorBatch CreateFrom(params IValidator[] validatorList)
        {
            return new ValidatorBatch(new List<IValidator>(validatorList));
        }

        public async Task ExecuteFor(AuthTokenValidatorData data)
        {
            foreach (var validator in this.validatorList)
            {
                await validator.Validate(data);
            }
        }

        public ValidatorBatch AddOptional(bool condition, IValidator optionalValidator)
        {
            if (condition)
            {
                this.validatorList.Add(optionalValidator);
            }
            return this;
        }

        private ValidatorBatch(List<IValidator> validatorList)
        {
            this.validatorList = validatorList;
        }
    }
}

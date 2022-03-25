namespace WebEid.Security.Validator.CertValidators
{
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    internal sealed class SubjectCertificateValidatorBatch
    {
        private readonly List<ISubjectCertificateValidator> validatorList;

        public static SubjectCertificateValidatorBatch CreateFrom(params ISubjectCertificateValidator[] validatorList) =>
            new SubjectCertificateValidatorBatch(new List<ISubjectCertificateValidator>(validatorList));

        public async Task ExecuteFor(X509Certificate2 subjectCertificate)
        {
            foreach (var validator in this.validatorList)
            {
                await validator.Validate(subjectCertificate);
            }
        }

        public SubjectCertificateValidatorBatch AddOptional(bool condition, ISubjectCertificateValidator optionalValidator)
        {
            if (condition)
            {
                this.validatorList.Add(optionalValidator);
            }
            return this;
        }

        private SubjectCertificateValidatorBatch(List<ISubjectCertificateValidator> validatorList) =>
            this.validatorList = validatorList;
    }
}

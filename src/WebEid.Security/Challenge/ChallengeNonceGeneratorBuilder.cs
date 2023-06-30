namespace WebEid.Security.Challenge
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// Builder for constructing <see cref="ChallengeNonceGenerator"/> instances.
    /// </summary>
    public class ChallengeNonceGeneratorBuilder
    {
        /// <summary>
        /// Static instance of random numbers generator.
        /// </summary>
        private static readonly RandomNumberGenerator StaticRandomNumberGenerator = RandomNumberGenerator.Create();

        /// <summary>
        /// Nonce's time-to-live duration.
        /// </summary>
        /// <remarks>
        /// When the time-to-live passes, the Nonce is considered to be expired.
        /// </remarks>
        public TimeSpan Duration { get; set; }

        /// <summary>
        /// Source of random bytes for the Nonce.
        /// </summary>
        public RandomNumberGenerator SecureRandomGenerator { get; set; }

        /// <summary>
        /// Challenge Nonce Store where the generated Challenge Nonces will be stored.
        /// </summary>
        public IChallengeNonceStore Store { get; set; }

        /// <summary>
        /// Constructs class in and initializes it with default values.
        /// </summary>
        /// <remarks>
        /// This is default constructor of the class. By default the <see cref="Duration"/> is set to 5 minutes and
        /// the <see cref="Store"/> property is holding <see cref="InMemoryChallengeNonceStore"/> instance.
        /// The <see cref="SecureRandomGenerator"/> property is referring to static instance of <see cref="RandomNumberGenerator"/>.
        /// </remarks>
        public ChallengeNonceGeneratorBuilder()
        {
            this.Duration = TimeSpan.FromMinutes(5.0D);
            this.SecureRandomGenerator = StaticRandomNumberGenerator;
            this.Store = new InMemoryChallengeNonceStore();
        }

        /// <summary>
        /// Override default Nonce time-to-live duration.
        /// </summary>
        /// <param name="duration">Challenge Nonce time-to-live duration.</param>
        /// <returns>Current Builder's instance.</returns>
        /// <remarks>
        /// When the time-to-live passes, the nonce is considered to be expired.
        /// </remarks>
        public ChallengeNonceGeneratorBuilder WithNonceTtl(TimeSpan duration)
        {
            this.Duration = duration;
            return this;
        }

        /// <summary>
        /// Sets the Challenge Nonce store where the generated Challenge Nonces will be stored.
        /// </summary>
        /// <param name="challengeNonceStore">Challenge Nonce store</param>
        /// <returns>Current Builder's instance.</returns>
        public ChallengeNonceGeneratorBuilder WithChallengeNonceStore(IChallengeNonceStore challengeNonceStore)
        {
            this.Store = challengeNonceStore;
            return this;
        }

        /// <summary>
        /// Sets the source of random bytes for the nonce.
        /// </summary>
        /// <param name="secureRandom">Secure random generator.</param>
        /// <returns>Current Builder's instance.</returns>
        public ChallengeNonceGeneratorBuilder WithSecureRandom(RandomNumberGenerator secureRandom)
        {
            this.SecureRandomGenerator = secureRandom;
            return this;
        }


        /// <summary>
        /// Validates the configuration and builds the <see cref="ChallengeNonceGenerator"/> instance.
        /// </summary>
        /// <returns>New Challenge Nonce generator instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown if <see cref="Duration"/> is zero.</exception>
        /// <exception cref="NullReferenceException">Thrown if either <see cref="SecureRandomGenerator"/> or <see cref="Store"/> are <see langword="null"/>.</exception>
        public IChallengeNonceGenerator Build()
        {
            if (this.Duration == TimeSpan.Zero)
            {
                throw new InvalidOperationException("Nonce TTL is zero");
            }

            if (this.SecureRandomGenerator is null)
            {
                throw new NullReferenceException("Secure Random Generator must not be null");
            }

            if (this.Store is null)
            {
                throw new NullReferenceException("Challenge Nonce Store must not be null");
            }

            var challengeNonceGenerator = new ChallengeNonceGenerator(this.SecureRandomGenerator, this.Store);
            _ = challengeNonceGenerator.GenerateAndStoreNonce(this.Duration);
            return challengeNonceGenerator;
        }
    }
}

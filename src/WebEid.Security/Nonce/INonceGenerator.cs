namespace WebEid.Security.Nonce
{
    /// <summary>
    /// Generates cryptographic nonces.
    /// </summary>
    public interface INonceGenerator
    {
        const int NonceLength = 32;
        /// <summary>
        /// Generates a cryptographic nonce, a large random number that can be used only once, and stores it in cache.
        /// </summary>
        /// <returns>Base64-encoded nonce</returns>
        string GenerateAndStoreNonce();
    }
}

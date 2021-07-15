namespace WebEid.Security.Validator
{
    internal enum SignatureAlgorithm
    {
        /// JWA name for <code>No digital signature or MAC performed</code>
        None,

        /// JWA algorithm name for <code>HMAC using SHA-256</code>
        Hs256,

        /// JWA algorithm name for <code>HMAC using SHA-384</code>
        Hs384,

        /// JWA algorithm name for <code>HMAC using SHA-512</code>
        Hs512,

        /// JWA algorithm name for <code>RSASSA-PKCS-v1_5 using SHA-256</code>
        Rs256,

        /// <summary>
        /// JWA algorithm name for <code>RSASSA-PKCS-v1_5 using SHA-384</code>
        /// </summary>
        Rs384,

        /// <summary>
        /// JWA algorithm name for <code>RSASSA-PKCS-v1_5 using SHA-512</code>
        /// </summary>
        Rs512,

        /// <summary>
        /// JWA algorithm name for <code>ECDSA using P-256 and SHA-256</code>
        /// </summary>
        Es256,

        /// <summary>
        /// JWA algorithm name for <code>ECDSA using P-384 and SHA-384</code>
        /// </summary>
        Es384,

        /// <summary>
        /// JWA algorithm name for <code>ECDSA using P-521 and SHA-512</code>
        /// </summary>
        Es512,

        /// <summary>
        /// JWA algorithm name for <code>RSASSA-PSS using SHA-256 and MGF1 with SHA-256</code>.
        /// </summary>
        Ps256,

        /// <summary>
        /// JWA algorithm name for <code>RSASSA-PSS using SHA-384 and MGF1 with SHA-384</code>. 
        /// </summary>
        Ps384,

        /// <summary>
        /// JWA algorithm name for <code>RSASSA-PSS using SHA-512 and MGF1 with SHA-512</code>. 
        /// </summary>
        Ps512
    }
}

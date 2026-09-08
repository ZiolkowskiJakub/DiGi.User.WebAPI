namespace DiGi.User.WebAPI.Constants
{
    /// <summary>
    /// Provides the PBKDF2 parameters new password credentials are derived with.
    /// </summary>
    public static class Password
    {
        /// <summary>
        /// The number of PBKDF2-HMAC-SHA256 iterations a new credential is stretched over, per the OWASP password
        /// storage guidance.
        /// <para>This value applies to credentials being created. Verification uses the iteration count stored on the
        /// credential itself, so raising this number costs nothing to the credentials already written.</para>
        /// </summary>
        public const int Iterations = 210000;

        /// <summary>
        /// The length in bytes of the random salt generated for a new credential.
        /// </summary>
        public const int SaltSize = 16;

        /// <summary>
        /// The length in bytes of the derived key stored as the password hash.
        /// </summary>
        public const int HashSize = 32;
    }
}

using DiGi.User.Classes;
using System;
using System.Security.Cryptography;

namespace DiGi.User.WebAPI
{
    public static partial class Query
    {
        /// <summary>
        /// Determines whether a password matches a stored credential, deriving it with the iteration count recorded on
        /// the credential and comparing the result in constant time.
        /// <para>Every branch that is not an exact match denies: a null credential, a blank password, a credential
        /// missing its hash or salt, a non-positive iteration count, and malformed Base64 all return false.</para>
        /// <para>A null credential is still verified against a fixed dummy salt before the answer is returned, so the
        /// time an unknown email takes to be rejected does not reveal that the account does not exist.</para>
        /// </summary>
        /// <param name="userCredential">The stored credential to verify against, or null when the user has none.</param>
        /// <param name="password">The plain text password presented by the caller.</param>
        /// <returns>True when the password derives to the stored hash; otherwise, false.</returns>
        public static bool IsPasswordValid(this UserCredential? userCredential, string? password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return false;
            }

            if (userCredential is null || string.IsNullOrWhiteSpace(userCredential.PasswordHash) || string.IsNullOrWhiteSpace(userCredential.PasswordSalt) || userCredential.PasswordIterations <= 0)
            {
                // Deny, but spend the same work an existing account would, so the response time of an unknown email
                // does not distinguish it from a known one. The salt is a fixed constant because nothing is compared
                // against the result.
                byte[] salt_Dummy = new byte[Constants.Password.SaltSize];
                _ = Rfc2898DeriveBytes.Pbkdf2(password, salt_Dummy, Constants.Password.Iterations, HashAlgorithmName.SHA256, Constants.Password.HashSize);
                return false;
            }

            byte[] hash_Stored;
            byte[] salt;

            try
            {
                hash_Stored = Convert.FromBase64String(userCredential.PasswordHash);
                salt = Convert.FromBase64String(userCredential.PasswordSalt);
            }
            catch (FormatException)
            {
                return false;
            }

            if (hash_Stored.Length == 0 || salt.Length == 0)
            {
                return false;
            }

            byte[] hash_Presented = Rfc2898DeriveBytes.Pbkdf2(password, salt, userCredential.PasswordIterations, HashAlgorithmName.SHA256, hash_Stored.Length);

            return CryptographicOperations.FixedTimeEquals(hash_Stored, hash_Presented);
        }
    }
}
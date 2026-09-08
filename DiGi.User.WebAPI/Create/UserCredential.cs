using DiGi.User.Classes;
using System;
using System.Security.Cryptography;

namespace DiGi.User.WebAPI
{
    public static partial class Create
    {
        /// <summary>
        /// Creates a <see cref="UserCredential"/> for a password, deriving it with PBKDF2-HMAC-SHA256 over a freshly
        /// generated random salt.
        /// <para>The salt is random per call, so creating a credential twice for the same password yields two different
        /// hashes and neither reveals that the passwords match.</para>
        /// <para>The credential is not stored by this method. Pass the result to
        /// <c>UserPostgreSQLConverter.SetUserCredentialAsync</c> to write it against an existing user.</para>
        /// </summary>
        /// <param name="email">The email address of the user the credential belongs to.</param>
        /// <param name="password">The plain text password to derive the credential from.</param>
        /// <returns>The derived <see cref="UserCredential"/>, or null when the email or the password is blank.</returns>
        public static UserCredential? UserCredential(string? email, string? password)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            {
                return null;
            }

            byte[] salt = RandomNumberGenerator.GetBytes(Constants.Password.SaltSize);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Constants.Password.Iterations, HashAlgorithmName.SHA256, Constants.Password.HashSize);

            return new UserCredential(email, Convert.ToBase64String(hash), Convert.ToBase64String(salt), Constants.Password.Iterations);
        }
    }
}
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DiGi.User.WebAPI
{
    public static partial class Create
    {
        /// <summary>
        /// Creates a signed JWT string identifying the given email, carrying a fresh JWT identifier (jti claim) and expiring after the session token lifetime.
        /// <para>Each call starts an independent session: the fresh jti makes the issued token individually revocable.</para>
        /// </summary>
        /// <param name="securityKeyManager">The security key manager providing the active signing key.</param>
        /// <param name="email">The email of the identity the token is issued for.</param>
        /// <returns>The signed token string, or null when the manager, its active key or the email is missing.</returns>
        public static string? TokenString(this DiGi.WebAPI.Classes.SecurityKeyManager? securityKeyManager, string? email)
        {
            if (securityKeyManager is null || string.IsNullOrWhiteSpace(email))
            {
                return null;
            }

            DiGi.WebAPI.Classes.SecurityKey? securityKey = securityKeyManager.GetActive();
            if (securityKey is null)
            {
                return null;
            }

            JwtSecurityTokenHandler tokenHandler = new();
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new ClaimsIdentity([new Claim(ClaimTypes.Email, email), new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))]),
                Expires = DateTime.UtcNow.Add(Constants.Session.TokenLifetime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(securityKey.GetBytes()), SecurityAlgorithms.HmacSha256Signature)
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
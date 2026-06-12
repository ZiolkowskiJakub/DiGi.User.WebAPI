using DiGi.User.Classes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DiGi.User.WebAPI.Classes
{
    /// <summary>
    /// Controller responsible for handling user-related operations, including authentication and access to protected data.
    /// </summary>
    [ApiController]
    [Route("user/[controller]")]
    public class UserController : DiGi.WebAPI.Classes.WebAPIController
    {
        private readonly DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserController"/> class.
        /// </summary>
        /// <param name="securityKeyManager">The security key manager used for managing cryptographic keys.</param>
        public UserController(DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager)
        {
            this.securityKeyManager = securityKeyManager;
        }

        // This endpoint is protected
        /// <summary>
        /// Retrieves secure data that requires authorization.
        /// </summary>
        /// <returns>An <see cref="IActionResult"/> containing the protected data or an authorization error.</returns>
        [HttpGet("secure-data")]
        [Authorize]
        public IActionResult GetProtectedData()
        {
            // Accessing the email from the token claims
            string userEmail = User.FindFirst(ClaimTypes.Email)?.Value ?? string.Empty;

            // Use your DLL libraries here to fetch data from PostgreSQL
            return Ok(new { Message = $"Hello {userEmail}, here is your private data from DB." });
        }

        // This endpoint generates the token based on Email
        /// <summary>
        /// Authenticates a user and generates a JWT security token.
        /// </summary>
        /// <param name="userLogin">The login credentials of the user.</param>
        /// <returns>An <see cref="IActionResult"/> containing the generated token upon success, or an unauthorized result.</returns>
        [HttpPost("login")]
        [AllowAnonymous]
        public IActionResult Login([FromBody] UserLogin userLogin)
        {
            // Here you would use your DLL and Npgsql to check if user exists in PostgreSQL
            if (userLogin.Email == "user@example.com")
            {
                JwtSecurityTokenHandler tokenHandler = new();
                byte[] key = securityKeyManager.GetActive()!.GetBytes();

                SecurityTokenDescriptor tokenDescriptor = new()
                {
                    Subject = new ClaimsIdentity([new Claim(ClaimTypes.Email, userLogin.Email)]),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };

                SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
                string tokenString = tokenHandler.WriteToken(token);

                return Ok(new { Token = tokenString });
            }

            return Unauthorized();
        }
    }
}
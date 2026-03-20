using DiGi.User.Classes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DiGi.User.WebAPI.Classes
{
    [ApiController]
    [Route("user/[controller]")]
    public class UserController : DiGi.WebAPI.Classes.WebAPIController
    {
        private readonly DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager;

        public UserController(DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager)
        {
            this.securityKeyManager = securityKeyManager;
        }

        // This endpoint is protected
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
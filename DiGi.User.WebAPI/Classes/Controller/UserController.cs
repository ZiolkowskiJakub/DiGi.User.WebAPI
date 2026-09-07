using DiGi.User.Classes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DiGi.User.WebAPI.Classes
{
    /// <summary>
    /// Controller responsible for handling user-related operations, including authentication, session lifecycle and access to protected data.
    /// </summary>
    [ApiController]
    [Route("user/[controller]")]
    public class UserController : DiGi.WebAPI.Classes.WebAPIController
    {
        private readonly DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager;

        private readonly DiGi.WebAPI.Classes.TokenRevocationStore tokenRevocationStore;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserController"/> class.
        /// </summary>
        /// <param name="securityKeyManager">The security key manager used for managing cryptographic keys.</param>
        /// <param name="tokenRevocationStore">The token revocation store used for terminating sessions.</param>
        public UserController(DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager, DiGi.WebAPI.Classes.TokenRevocationStore tokenRevocationStore)
        {
            this.securityKeyManager = securityKeyManager;
            this.tokenRevocationStore = tokenRevocationStore;
        }

        // This endpoint is protected
        /// <summary>
        /// Retrieves secure data that requires authorization.
        /// </summary>
        /// <returns>An <see cref="IActionResult"/> containing the protected data or an authorization error.</returns>
        [HttpGet("secure-data", Name = $"{nameof(UserController)}_{nameof(GetProtectedData)}")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult GetProtectedData()
        {
            // Accessing the email from the token claims
            string userEmail = User.FindFirst(ClaimTypes.Email)?.Value ?? string.Empty;

            // Use your DLL libraries here to fetch data from PostgreSQL
            return Ok(new { Message = $"Hello {userEmail}, here is your private data from DB." });
        }

        // This endpoint generates the token based on Email
        /// <summary>
        /// Authenticates a user and generates a JWT security token carrying a fresh session identifier (jti claim).
        /// </summary>
        /// <param name="userLogin">The login credentials of the user.</param>
        /// <returns>An <see cref="IActionResult"/> containing the generated token upon success, or an unauthorized result.</returns>
        [HttpPost("login", Name = $"{nameof(UserController)}_{nameof(Login)}")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public IActionResult Login([FromBody] UserLogin userLogin)
        {
            // Here you would use your DLL and Npgsql to check if user exists in PostgreSQL
            if (userLogin.Email == "user@example.com")
            {
                string? tokenString = securityKeyManager.TokenString(userLogin.Email);
                if (tokenString is null)
                {
                    return StatusCode(500);
                }

                return Ok(new { Token = tokenString });
            }

            return Unauthorized();
        }

        /// <summary>
        /// Introspects the current session, returning the identity and token metadata of the presented token.
        /// </summary>
        /// <returns>An <see cref="IActionResult"/> containing the session information, or an authorization error.</returns>
        [HttpGet("session", Name = $"{nameof(UserController)}_{nameof(GetSession)}")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult GetSession()
        {
            JwtSecurityToken? jwtSecurityToken = ReadPresentedToken();
            if (jwtSecurityToken is null)
            {
                return Unauthorized();
            }

            return Ok(new
            {
                Email = User.FindFirst(ClaimTypes.Email)?.Value,
                Jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value,
                IssuedAt = new DateTimeOffset(jwtSecurityToken.IssuedAt, TimeSpan.Zero),
                ExpiresAt = new DateTimeOffset(jwtSecurityToken.ValidTo, TimeSpan.Zero)
            });
        }

        /// <summary>
        /// Issues a new token for the identity of the presented token, starting an independent session; the presented token remains valid until its own expiration.
        /// </summary>
        /// <returns>An <see cref="IActionResult"/> containing the new token, or an authorization error.</returns>
        [HttpPost("session/refresh", Name = $"{nameof(UserController)}_{nameof(Refresh)}")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public IActionResult Refresh()
        {
            string? email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrWhiteSpace(email))
            {
                return Unauthorized();
            }

            string? tokenString = securityKeyManager.TokenString(email);
            if (tokenString is null)
            {
                return StatusCode(500);
            }

            return Ok(new { Token = tokenString });
        }

        /// <summary>
        /// Terminates the current session by revoking the presented token until its natural expiration; every subsequent request carrying it is rejected.
        /// </summary>
        /// <returns>An <see cref="IActionResult"/> confirming the revocation, a bad request when the token cannot be revoked, or an authorization error.</returns>
        [HttpPost("logout", Name = $"{nameof(UserController)}_{nameof(Logout)}")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult Logout()
        {
            string? jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (string.IsNullOrWhiteSpace(jti))
            {
                return BadRequest(new { Message = "This token does not carry a session identifier (jti) and cannot be revoked. Please log in again to receive a new token." });
            }

            JwtSecurityToken? jwtSecurityToken = ReadPresentedToken();
            if (jwtSecurityToken is null)
            {
                return Unauthorized();
            }

            tokenRevocationStore.Revoke(jti, new DateTimeOffset(jwtSecurityToken.ValidTo, TimeSpan.Zero));

            return Ok(new { Message = "Session terminated. The presented token is revoked until its expiration." });
        }

        /// <summary>
        /// Reads the bearer token from the Authorization header, already validated by the authentication middleware for any authorized action.
        /// </summary>
        /// <returns>The presented <see cref="JwtSecurityToken"/>, or null when the header does not carry a bearer token.</returns>
        private JwtSecurityToken? ReadPresentedToken()
        {
            string? authorizationHeader = Request.Headers.Authorization;
            if (authorizationHeader is null || !authorizationHeader.StartsWith("Bearer ", StringComparison.Ordinal))
            {
                return null;
            }

            JwtSecurityTokenHandler tokenHandler = new();
            return tokenHandler.ReadJwtToken(authorizationHeader["Bearer ".Length..]);
        }
    }
}

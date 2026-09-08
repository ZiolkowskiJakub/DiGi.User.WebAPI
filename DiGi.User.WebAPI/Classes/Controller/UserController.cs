using DiGi.User.Classes;
using DiGi.User.PostgreSQL.Classes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace DiGi.User.WebAPI.Classes
{
    /// <summary>
    /// Controller responsible for handling user-related operations, including authentication, session lifecycle and access to protected data.
    /// </summary>
    [ApiController]
    [Route("[controller]")]
    public class UserController : DiGi.WebAPI.Classes.WebAPIController
    {
        private readonly DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager;

        private readonly DiGi.WebAPI.Classes.TokenRevocationStore tokenRevocationStore;

        private readonly UserPostgreSQLConverter userPostgreSQLConverter;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserController"/> class.
        /// <para>This is deliberately the only public constructor: a second one makes the controller ambiguous to the
        /// activator and every endpoint answers 500 at request time, with the build still green.</para>
        /// </summary>
        /// <param name="securityKeyManager">The security key manager used for managing cryptographic keys.</param>
        /// <param name="tokenRevocationStore">The token revocation store used for terminating sessions.</param>
        /// <param name="userPostgreSQLConverter">The converter used to read users and their credentials from PostgreSQL.</param>
        public UserController(DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager, DiGi.WebAPI.Classes.TokenRevocationStore tokenRevocationStore, UserPostgreSQLConverter userPostgreSQLConverter)
        {
            this.securityKeyManager = securityKeyManager;
            this.tokenRevocationStore = tokenRevocationStore;
            this.userPostgreSQLConverter = userPostgreSQLConverter;
        }

        // This endpoint is protected
        /// <summary>
        /// Retrieves the stored record of the authenticated user.
        /// <para>The record is read for the email carried by the presented token, so a caller can only ever read itself.
        /// The credential columns are not part of the <see cref="DiGi.User.Classes.User"/> payload and are never returned.</para>
        /// </summary>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        /// <returns>An <see cref="IActionResult"/> containing the stored user, a not found result, or an authorization error.</returns>
        [HttpGet("secure-data", Name = $"{nameof(UserController)}_{nameof(GetProtectedDataAsync)}")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [Authorize]
        [ProducesResponseType(typeof(DiGi.User.Classes.User), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GetProtectedDataAsync(CancellationToken cancellationToken = default)
        {
            Serilog.Modify.Log("{Type}:{Name} started", nameof(UserController), nameof(GetProtectedDataAsync));

            // Accessing the email from the token claims
            string userEmail = User.FindFirst(ClaimTypes.Email)?.Value ?? string.Empty;
            if (string.IsNullOrWhiteSpace(userEmail))
            {
                return Unauthorized();
            }

            if (userPostgreSQLConverter is null)
            {
                Serilog.Modify.Log(Serilog.Enums.LogEventLevel.Warning, "No {Type} available", nameof(UserPostgreSQLConverter));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }

            DiGi.User.Classes.User? user = await userPostgreSQLConverter.GetUserByEmailAsync(userEmail, cancellationToken: cancellationToken);

            string? json = Core.Convert.ToSystem_String(user);
            if (string.IsNullOrWhiteSpace(json))
            {
                return NotFound();
            }

            return Content(json, "application/json");
        }

        // This endpoint generates the token based on Email
        /// <summary>
        /// Authenticates a user against the credential stored in PostgreSQL and generates a JWT security token carrying a
        /// fresh session identifier (jti claim).
        /// <para>Every outcome that is not an exact password match answers 401, and all of them take the same time: an
        /// unknown email, an account whose credential was never set, and a wrong password are indistinguishable to the
        /// caller. The server log distinguishes them.</para>
        /// </summary>
        /// <param name="userLogin">The login credentials of the user.</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        /// <returns>An <see cref="IActionResult"/> containing the generated token upon success, or an unauthorized result.</returns>
        [HttpPost("login", Name = $"{nameof(UserController)}_{nameof(LoginAsync)}")]
        [ApiExplorerSettings(IgnoreApi = false)]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> LoginAsync([FromBody] UserLogin userLogin, CancellationToken cancellationToken = default)
        {
            // The submitted password must never reach the log, so only the email is ever recorded.
            Serilog.Modify.Log("{Type}:{Name} started", nameof(UserController), nameof(LoginAsync));

            if (userLogin is null || string.IsNullOrWhiteSpace(userLogin.Email) || string.IsNullOrWhiteSpace(userLogin.Password))
            {
                Serilog.Modify.Log(Serilog.Enums.LogEventLevel.Warning, "Login rejected: incomplete credentials");
                return Unauthorized();
            }

            if (userPostgreSQLConverter is null)
            {
                // A server fault rather than a bad credential, so it is not reported as one.
                Serilog.Modify.Log(Serilog.Enums.LogEventLevel.Warning, "No {Type} available", nameof(UserPostgreSQLConverter));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }

            // A missing user, a user with no credential and a wrong password all land here, and IsPasswordValid spends
            // the same work on each, so the three are indistinguishable to the caller. They are logged apart.
            UserCredential? userCredential = await userPostgreSQLConverter.GetUserCredentialAsync(userLogin.Email, cancellationToken: cancellationToken);
            if (!userCredential.IsPasswordValid(userLogin.Password))
            {
                Serilog.Modify.Log(Serilog.Enums.LogEventLevel.Warning, userCredential is null ? "Login rejected: no stored credential for {Email}" : "Login rejected: password mismatch for {Email}", userLogin.Email);
                return Unauthorized();
            }

            string? tokenString = securityKeyManager.TokenString(userLogin.Email);
            if (tokenString is null)
            {
                Serilog.Modify.Log(Serilog.Enums.LogEventLevel.Error, "Token could not be issued for {Email}", userLogin.Email);
                return StatusCode(StatusCodes.Status500InternalServerError);
            }

            Serilog.Modify.Log("Login accepted for {Email}", userLogin.Email);
            return Ok(new { Token = tokenString });
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
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DiGi.User.WebAPI
{
    public static partial class Modify
    {
        /// <summary>
        /// Initializes the authentication and authorization services for the Web API, including security key management and token revocation.
        /// </summary>
        /// <param name="serviceCollection">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        public static async Task InitializeAsync(this IServiceCollection serviceCollection)
        {
            if (serviceCollection is null)
            {
                return;
            }

            DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager = new();
            securityKeyManager.Generate();

            serviceCollection.AddSingleton(securityKeyManager);

            DiGi.WebAPI.Classes.TokenRevocationStore tokenRevocationStore = new();
            serviceCollection.AddSingleton(tokenRevocationStore);

            serviceCollection.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = tokenValidatedContext =>
                    {
                        string? jti = tokenValidatedContext.Principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
                        if (tokenRevocationStore.IsRevoked(jti))
                        {
                            tokenValidatedContext.Fail("Token has been revoked.");
                        }

                        return Task.CompletedTask;
                    }
                };

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,

                    IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                    {
                        List<SymmetricSecurityKey> symmetricSecurityKeys = [];
                        foreach (DiGi.WebAPI.Classes.SecurityKey securityKey in securityKeyManager.SecurityKeys)
                        {
                            symmetricSecurityKeys.Add(new SymmetricSecurityKey(securityKey.GetBytes()));
                        }

                        return symmetricSecurityKeys;
                    }
                };
            });

            serviceCollection.AddAuthorization();
        }
    }
}
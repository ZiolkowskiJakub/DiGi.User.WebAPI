using DiGi.User.PostgreSQL.Classes;
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
        /// Initializes the authentication and authorization services for the Web API, including security key management,
        /// token revocation and the PostgreSQL converters the controllers read users from.
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

            // Converters are registered by concrete type so a controller can inject UserPostgreSQLConverter directly,
            // matching DiGi.GIS.WebAPI.Modify.InitializeAsync.
            UserPostgreSQLConverterManager? userPostgreSQLConverterManager = PostgreSQL.Create.UserPostgreSQLConverterManager();

            List<PostgreSQL.Interfaces.IUserPostgreSQLConverter>? userPostgreSQLConverters = userPostgreSQLConverterManager?.GetPostgreSQLConverters<PostgreSQL.Interfaces.IUserPostgreSQLConverter>();
            if (userPostgreSQLConverters is not null)
            {
                foreach (PostgreSQL.Interfaces.IUserPostgreSQLConverter userPostgreSQLConverter in userPostgreSQLConverters)
                {
                    serviceCollection.AddSingleton(userPostgreSQLConverter.GetType(), userPostgreSQLConverter);
                }
            }

            // UserController takes a UserPostgreSQLConverter, and a controller is activated per request: without a
            // registration, activation throws and EVERY endpoint answers 500 - including session, refresh and logout,
            // which never touch the database. A converter with no connection data keeps those working and makes login
            // deny by default, because its own guards return null before a connection is ever opened.
            if (userPostgreSQLConverters is null || userPostgreSQLConverters.Count == 0)
            {
                Serilog.Modify.Log(Serilog.Enums.LogEventLevel.Warning, "No {Type} configured. Place {FileName} beside the assembly. Login denies every request until it is present.", nameof(UserPostgreSQLConverter), PostgreSQL.Constants.FileName.PostgreSQL_Main);
                serviceCollection.AddSingleton(new UserPostgreSQLConverter(null));
            }
        }
    }
}
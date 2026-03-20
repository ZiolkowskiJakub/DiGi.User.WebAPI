using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DiGi.User.WebAPI
{
    public static partial class Modify
    {
        public static async Task InitializeAsync(this IServiceCollection serviceCollection)
        {
            if (serviceCollection is null)
            {
                return;
            }

            DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager = new();
            securityKeyManager.Generate();

            serviceCollection.AddSingleton(securityKeyManager);

            serviceCollection.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
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
using System.Collections.Generic;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;

namespace WebHost.Configuration
{
    public static class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new[]
            {
                new Client 
                {
                    ClientName = "MVC Client",
                    ClientId = "mvc",
                    Enabled = true,
                    Flow = Flows.Implicit,
                    RequireConsent = true,
                    AllowRememberConsent = true,
                    RedirectUris = new List<string>
                    {
                        "https://localhost:44316/account/signInCallback"
                    },
                    PostLogoutRedirectUris = new List<string>
                    {
                        "http://localhost:44316/"
                    },
                    AllowedScopes = new List<string> {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.Email
                },
                AccessTokenType = AccessTokenType.Jwt
                }
                /*
                new Client
                {
                    ClientName = "MVC Client (service communication)",   
                    ClientId = "mvc_service",
                    Flow = Flows.ClientCredentials,

                    ClientSecrets = new List<Secret>
                    {
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes = new List<string>
                    {
                        "sampleApi"
                    }
                }
                */
            };
        }
    }
}
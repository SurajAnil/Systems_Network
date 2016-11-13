using System.Collections.Generic;
using System.Security.Claims;
using IdentityServer3.Core;
using IdentityServer3.Core.Services.InMemory;

namespace WebHost.Configuration
{
    public static class Users
    {
        public static List<InMemoryUser> Get()
        {
            return new List<InMemoryUser>
            {
                new InMemoryUser
                {
                    Username = "sbennur",
                    Password = "pass",
                    Subject = "1",
                    Claims = new List<Claim>
                    {
                        new Claim(Constants.ClaimTypes.GivenName, "Suraj"),
                        new Claim(Constants.ClaimTypes.FamilyName, "Bennur"),
                        new Claim(Constants.ClaimTypes.Email, "sbennur@outlook.com"),
                        new Claim(Constants.ClaimTypes.Role, "admin")
                    }
                }
            };
        }
    }
}
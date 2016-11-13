using Microsoft.Owin;
using Owin;
using IdentityServer3.Core.Configuration;
using Serilog;
//using IdentityServer3.Host.Config;
using WebHost.Configuration;

[assembly: OwinStartup(typeof(WebHost.Startup))]

namespace WebHost
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            
            Log.Logger = new LoggerConfiguration()
                .WriteTo.Trace(outputTemplate: "{Timestamp} [{Level}] ({Name}){NewLine} {Message}{NewLine}{Exception}")
                .CreateLogger();
                
            
                
            var factory = new IdentityServerServiceFactory()
                        .UseInMemoryUsers(Users.Get())
                        .UseInMemoryClients(Clients.Get())
                        .UseInMemoryScopes(Scopes.Get());

            var options = new IdentityServerOptions
            {
                RequireSsl = true,
                SigningCertificate = Cert.Load(),
                
                Factory = factory,
                AuthenticationOptions = new AuthenticationOptions
                {
                    EnablePostSignOutAutoRedirect = true
                }

            };


            app.Map("/core", idsrvApp =>
            {
                idsrvApp.UseIdentityServer(options);
            });
        }
    }
}
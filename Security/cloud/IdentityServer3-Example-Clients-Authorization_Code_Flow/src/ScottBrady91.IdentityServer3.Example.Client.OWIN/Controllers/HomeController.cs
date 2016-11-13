using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Thinktecture.IdentityModel.Clients;
using Thinktecture.IdentityModel.Constants;
using Claim = System.Security.Claims.Claim;

namespace IdentityServer3.Example.Client.OWIN.Controllers
{
    public sealed class HomeController : Controller
    {
        public static Boolean isAuth=false;
        public static string acToken = "";
        public ActionResult Index()
        {
            
            

            var url = "https://localhost:44333/core/connect/authorize"+
                "?client_id=acfClient" +
                "&redirect_uri=https://localhost:44305/Home/AuthorizationCallback" +
                "&response_type=code" +
                "&scope=openid profile" +
                "&response_mode=form_post";

            return Redirect(url);
            //return this.View();
        }

        public ActionResult AuthorizationCallback(string code, string state, string error)
        {
            if (code!=null)
            {



                var tokenUrl = "https://localhost:44333/core/connect/token";
                var client = new OAuth2Client(new Uri(tokenUrl), "acfClient", "idsrv3test");


                var requestResult = client.RequestAccessTokenCode(code,
                    new Uri("https://localhost:44305/Home/AuthorizationCallback"));

                var claims = new[]
                {
                    new Claim("access_token", requestResult.AccessToken),
                };

                var identity = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);

                Request.GetOwinContext().Authentication.SignIn(identity);
                if (Request.IsAuthenticated)
                    Console.WriteLine("Is authenticated");

                if (identity.IsAuthenticated)
                {
                    var claimsPrincipal = User as ClaimsPrincipal;
                    isAuth = true;
                    acToken = requestResult.AccessToken;
                    return Content(requestResult.AccessToken);
                    
                }
            }

            return Content("ERROR!\nPlease redirect to login page to validate yourself!");
            //return Redirect("/");
            //return Content(requestResult.AccessToken);
        }
    }
}
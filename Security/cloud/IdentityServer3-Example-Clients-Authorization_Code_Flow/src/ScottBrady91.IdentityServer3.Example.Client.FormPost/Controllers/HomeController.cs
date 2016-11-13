using System.Web.Mvc;

namespace IdentityServer3.Example.Client.FormPost.Controllers
{
    public sealed class HomeController : Controller
    {
        public ActionResult Index()
        {
            return this.View();
        }
    }
}
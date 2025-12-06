using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(ResiApp.Startup))]
namespace ResiApp
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
        }
    }
}



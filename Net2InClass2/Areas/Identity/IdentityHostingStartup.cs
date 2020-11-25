using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Net2InClass2.Data;

[assembly: HostingStartup(typeof(Net2InClass2.Areas.Identity.IdentityHostingStartup))]
namespace Net2InClass2.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) =>
            {
                services.Configure<IdentityOptions>(options =>
                {
                    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(10);
                    options.Lockout.MaxFailedAccessAttempts = 3;
                    options.Lockout.AllowedForNewUsers = true;
                });
            });
        }
    }
}
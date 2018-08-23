using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Microsoft.AspNetCore.Authentication
{
    public static class IAppBuilderExtension
    {
        public static IServiceCollection AddAuthProxy(this IServiceCollection collection, Action<AuthProxyOptions> proxyOptions, Action<AadAuthenticationOptions> authOptions)
        {
            collection.Configure(proxyOptions);
            collection.Configure(authOptions);

            var aadSettings = new AadAuthenticationOptions();
            authOptions(aadSettings);
            
            collection.AddAuthentication(o =>
                {
                    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                .AddAzureAdBearer(authOptions)
                .AddOpenIdConnect(options =>
                {
                    options.Authority =  $"https://login.microsoftonline.com/{aadSettings.Tenant}";
                    options.ClientId = aadSettings.ClientId;
                    options.ResponseType = OpenIdConnectResponseType.IdToken;
                    options.CallbackPath = aadSettings.CallbackPath;
                    options.SaveTokens = true;
                })
                .AddCookie();

            return collection;
        }

        public static IApplicationBuilder UseAuthProxy(this IApplicationBuilder builder)
        {
            var proxyOptions = builder.ApplicationServices.GetService<IOptions<AuthProxyOptions>>().Value;            

            builder.UseAuthentication();

            builder.UseMiddleware<AuthProxyMiddleware>();

            builder.MapWhen(MustForward, b => b.RunProxy(new ProxyOptions
            {
                Scheme = "http",
                Host = "localhost",
                Port = proxyOptions.ForwardPort,
                BackChannelMessageHandler = new AuthBackChannelHandler(),
            }));

            return builder;
        }

        private static bool MustForward(HttpContext context)
        {
            if (context.Request.Path.StartsWithSegments(new PathString("/me")) || 
                context.Request.Path.StartsWithSegments(new PathString("/login")))
            {
                return false;
            }

            return true;
        }
    }

    public class AuthProxyMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly List<string> _anonymousPaths;        

        public AuthProxyMiddleware(RequestDelegate next, IOptions<AuthProxyOptions> authProxyOptions)
        {
            _next = next;
            _anonymousPaths = authProxyOptions.Value.AnonymousPaths?.Split(',').ToList() ?? new List<string>();
        }

        public async Task Invoke(HttpContext context)
        {
            // Authenticated?
            if (context.User.Identity.IsAuthenticated)
            {
                await _next(context);
            }
            else if (_anonymousPaths.Any(p => context.Request.Path.StartsWithSegments(p)))
            {
                await _next(context);
            }
            else if (context.Request.Path.StartsWithSegments("/login"))
            {
                await _next(context);
            }
            else
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                await context.Response.WriteAsync("Unauthorized: 401");
            }
        }

    }
}

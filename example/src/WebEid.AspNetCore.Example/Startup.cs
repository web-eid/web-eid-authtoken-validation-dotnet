// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example
{
    using System;
    using System.Configuration;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using Certificates;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.HttpOverrides;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;
    using Options;
    using Security.Challenge;
    using Security.Validator;
    using Services;
    using Signing;

    public class Startup(IConfiguration configuration, IWebHostEnvironment environment)
    {
        private IConfiguration Configuration { get; } = configuration;
        private IWebHostEnvironment CurrentEnvironment { get; } = environment;

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger("Web-eId ASP.NET Core Example");
            services.AddSingleton(logger);

            services.AddRazorPages(options => options.Conventions.AuthorizePage("/welcome", "LoggedInOnly"));

            services
                .AddAuthorizationBuilder()
                .AddPolicy("LoggedInOnly", policy =>
                {
                    policy.AuthenticationSchemes.Add(CookieAuthenticationDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new LoggedInRequirement());
                });

            services.AddSingleton<IAuthorizationHandler, LoggedInAuthorizationHandler>();

            services.AddControllers();
            services.AddMvc(options => options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.Cookie.Name = "__Host-WebEid.AspNetCore.Example.Auth";
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    // Set to "strict" if Web eID for Mobile flow is not used - this would restrict sending back the
                    // authentication response in the Web eID for Mobile flow.
                    options.Cookie.SameSite = SameSiteMode.Lax;
                    options.Events.OnRedirectToLogin = context =>
                    {
                        context.Response.Redirect("/");
                        return Task.CompletedTask;
                    };
                    options.Events.OnRedirectToAccessDenied = context =>
                    {
                        context.Response.Redirect("/");
                        return Task.CompletedTask;
                    };
                });

            services.AddSession(options =>
            {
                options.Cookie.Name = "__Host-WebEid.AspNetCore.Example.Session";
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                // Set to "strict" if Web eID for Mobile flow is not used - this would restrict sending back the
                // authentication response in the Web eID for Mobile flow.
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.IdleTimeout = TimeSpan.FromSeconds(300);
                options.Cookie.IsEssential = true;
            });

            services.AddOptions<WebEidMobileOptions>()
                .Bind(Configuration.GetSection("WebEidMobile"))
                .ValidateDataAnnotations()
                .ValidateOnStart();

            services.AddSingleton<MobileRequestUriBuilder>();

            var url = GetOriginUrl(Configuration);

            services.AddSingleton(new AuthTokenValidatorBuilder(logger)
                .WithSiteOrigin(url)
                .WithTrustedCertificateAuthorities(CertificateLoader.LoadTrustedCaCertificatesFromDisk(CurrentEnvironment.IsDevelopment()))
                .Build());

            services.AddSingleton(RandomNumberGenerator.Create());
            services.AddSingleton<SigningService>();
            services.AddScoped<MobileSigningService>();
            services.AddSingleton<DigiDocConfiguration>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddSingleton<IChallengeNonceStore, SessionBackedChallengeNonceStore>();
            services.AddSingleton<IChallengeNonceGenerator, ChallengeNonceGenerator>();

            services.AddAntiforgery(options => options.Cookie.SecurePolicy = CookieSecurePolicy.Always);

            services.AddHostedService<ContainerCleanupService>();

            // Add support for running behind a TLS terminating proxy.
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                // Only use this if you're behind a known proxy:
                options.KnownIPNetworks.Clear();
                options.KnownProxies.Clear();
            });
        }

        private static Uri GetOriginUrl(IConfiguration configuration)
        {
            var url = configuration["OriginUrl"];
            if (string.IsNullOrWhiteSpace(url))
            {
                throw new ConfigurationErrorsException("OriginUrl is not configured");
            }

            return new Uri(url);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Add support for running behind a TLS terminating proxy.
            app.UseForwardedHeaders();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseHttpsRedirection();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });
        }
    }
}

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using MVP_1B2;
using MVP_1B2.Data;
using MVP_1B2.Middleware;
using MVP_1B2.Models;
using MVP_1B2.Services;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Authentication;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // ============================================================
        // HTTPS + Client Certificate (mTLS) demonstration
        // ============================================================

        builder.WebHost.ConfigureKestrel(options =>
        {
            // ------------------------------------------------------------
            // Normal HTTP endpoint
            // ------------------------------------------------------------
            options.ListenLocalhost(5148);

            // ------------------------------------------------------------
            // Normal HTTPS endpoint
            // Used by the main application, Microsoft SSO, Twilio 2FA
            // ------------------------------------------------------------
            options.ListenAnyIP(
                7148,
                listenOptions =>
                {
                    listenOptions.UseHttps();
                });

            // ------------------------------------------------------------
            // HTTPS + Client Certificate endpoint
            // Security demonstration
            // ------------------------------------------------------------
            options.ListenAnyIP(
                7443,
                listenOptions =>
                {
                    listenOptions.UseHttps(
                        httpsOptions =>
                        {
                            httpsOptions.ClientCertificateMode =
                                ClientCertificateMode.RequireCertificate;

                            // TLS 1.2 for easier Wireshark demonstration
                            httpsOptions.SslProtocols =
                                SslProtocols.Tls12;

                            var expectedThumbprint =
                                builder.Configuration[
                                    "ClientCertificate:Thumbprint"];

                            httpsOptions.ClientCertificateValidation =
                                (certificate, chain, sslPolicyErrors) =>
                                {
                                    if (certificate == null)
                                    {
                                        return false;
                                    }

                                    return string.Equals(
                                        certificate.Thumbprint,
                                        expectedThumbprint,
                                        StringComparison.OrdinalIgnoreCase);
                                };
                        });
                });
        });

        builder.Services.AddSingleton<AesGcmEncryptionService>();
        builder.Services.AddSingleton<NonRepudiationService>();
        builder.Services.AddScoped<AuditService>();

        // Database
        builder.Services.AddDbContext<ClientContext>(options =>
            options.UseSqlServer(
                builder.Configuration.GetConnectionString("DefaultConnection")
                ?? throw new InvalidOperationException(
                    "Connection string 'DefaultConnection' not found.")));

        // ASP.NET Core Identity
        builder.Services
            .AddDefaultIdentity<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;

                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 12;

                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan =
                    TimeSpan.FromMinutes(15);
            })
            .AddRoles<IdentityRole>()
            .AddDefaultTokenProviders()
            .AddTokenProvider<TwilioTwoFactorTokenProvider>("TwilioSms")
            .AddEntityFrameworkStores<ClientContext>();

        // MVC
        builder.Services.AddControllersWithViews();

        // Upload size limit
        builder.Services.Configure<FormOptions>(options =>
        {
            options.MultipartBodyLengthLimit = 104857600;
        });

        // Authorization
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy(
                "AdministratorOnly",
                policy =>
                {
                    policy.RequireRole("Administrator");
                });
        });

        // Identity Razor Pages
        builder.Services.AddRazorPages(options =>
        {
            options.Conventions.AuthorizeAreaPage(
                "Identity",
                "/Account/Register",
                "AdministratorOnly");
        });

        // IP filtering
        builder.Services.Configure<IpFilteringOptions>(
            builder.Configuration.GetSection("IPFiltering"));

        // Twilio
        builder.Services.Configure<TwilioOptions>(
            builder.Configuration.GetSection("Twilio"));

        builder.Services.AddScoped<
            ITwoFactorService,
            TwilioTwoFactorService>();


        // Azure / Microsoft Entra SSO
        builder.Services
            .AddAuthentication()
            .AddMicrosoftIdentityWebApp(
                options =>
                {
                    builder.Configuration.Bind(
                        "AzureAd",
                        options);

                    options.SignInScheme =
                        IdentityConstants.ExternalScheme;
                },
                openIdConnectScheme: "AzureAD",
                cookieScheme: null);


        //License
       // builder.Services.Configure<LicenseOptions>(
       // builder.Configuration.GetSection("License"));

       // builder.Services.AddSingleton<
        //   ILicenseService,
        //    LicenseService>();
        
        //Stream cipher
        builder.Services.AddSingleton<CustomStreamCipherService>();
        builder.Services.AddSingleton<LicenseVerificationService>();

        // Build application
        var app = builder.Build();

        // ============================================================
        // License verification at application startup
        // ============================================================

        using (var scope = app.Services.CreateScope())
        {
            var licenseService =
                scope.ServiceProvider
                    .GetRequiredService<LicenseVerificationService>();

            var licensePath =
                Path.Combine(
                    app.Environment.ContentRootPath,
                    "App_Data",
                    "license.json");

            Console.WriteLine(
                $"License path: {licensePath}");

            Console.WriteLine(
                $"License exists: {File.Exists(licensePath)}");

            var license =
                licenseService.LoadLicense(
                    licensePath);


            bool signatureValid =
                licenseService.VerifySignature(license);

            bool dateValid =
                licenseService.IsWithinValidityPeriod(
                    license.License);

            bool licenseValid = signatureValid && dateValid;

            Console.WriteLine(
                $"License ID: {license.License.LicenseId}");

            Console.WriteLine(
                $"License signature valid: {signatureValid}");

            Console.WriteLine(
                $"License date valid: {dateValid}");

            Console.WriteLine(
                $"Valid from: {license.License.ValidFromUtc:O}");

            Console.WriteLine(
                $"Valid until: {license.License.ValidUntilUtc:O}");

            Console.WriteLine(
                $"Current UTC: {DateTimeOffset.UtcNow:O}");

         
            Console.WriteLine(
                $"Overall license valid: {licenseValid}");

            Console.WriteLine(
                $"License verified: {license.License.LicenseId}");

            Console.WriteLine(
                $"License type: {license.License.LicenseType}");

            if (!licenseValid)
            {
                Console.WriteLine();
                Console.WriteLine(
                    "WARNING: The application license is not valid.");
                Console.WriteLine(
                    "Visit /License/Status for more information.");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine(
                    $"License verified: {license.License.LicenseId}");
                Console.WriteLine();
            }
        }


        // Seed Identity roles/admin
        using (var scope = app.Services.CreateScope())
        {
            await IdentitySeeder.SeedRolesAsync(
                scope.ServiceProvider);

            await IdentitySeeder.SeedAdminAsync(
                scope.ServiceProvider);
        }

        // Seed Identity roles/admin
        using (var scope = app.Services.CreateScope())
        {
            await IdentitySeeder.SeedRolesAsync(
                scope.ServiceProvider);

            await IdentitySeeder.SeedAdminAsync(
                scope.ServiceProvider);
        }

        // HTTP pipeline
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Home/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        app.UseStaticFiles();

        app.UseRouting();

        app.UseMiddleware<IpFilteringMiddleware>();

        app.UseAuthentication();

       // app.UseMiddleware<LicenseValidationMiddleware>();

        app.UseAuthorization();


        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        app.MapRazorPages();

        app.MapGet(
        "/certificate-test",
        async context =>
        {
            var certificate =
                await context.Connection.GetClientCertificateAsync();

            if (certificate == null)
            {
                context.Response.StatusCode = 403;

                await context.Response.WriteAsync(
                    "Client certificate not provided.");

                return;
            }

            await context.Response.WriteAsync(
                "Client certificate accepted.\n\n" +
                $"Subject: {certificate.Subject}\n" +
                $"Issuer: {certificate.Issuer}\n" +
                $"Thumbprint: {certificate.Thumbprint}\n" +
                $"Not After: {certificate.NotAfter:O}");
        });

        app.MapGet("/ip-test", (
        HttpContext context) =>
            {
                var ip =
                    context.Connection.RemoteIpAddress?.ToString()
                    ?? "unknown";

                return Results.Ok(new
                {
                    Message = "IP filtering allowed this request.",
                    RemoteIP = ip
                });
            });

        app.Run();
    }
}

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Graph;
using Microsoft.Graph.Core;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;
using Microsoft.Identity.Web.UI;
using Microsoft.Kiota.Abstractions;
using Microsoft.Kiota.Abstractions.Authentication;
using System.Net.Http.Headers;
using static OIDCDemoApp.Models.UserProfile;
using static SimpleAuthProvider;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Add session support
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.Name = "OIDCDemoApp.Session";
});

// Add HttpClient factory
builder.Services.AddHttpClient();

// Configure authentication with token cache
builder.Services
    .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(options => {
        builder.Configuration.Bind("AzureAd", options);

        // Set up configuration
        var tenantId = "volvogroupextiddev.onmicrosoft.com";//Test :-  "volvogroupextid.onmicrosoft.com";
        
        // Use the generic CIAM authority format
        options.Authority = $"https://volvogroupextiddev.ciamlogin.com/{tenantId}";
        options.MetadataAddress = $"https://volvogroupextiddev.ciamlogin.com/{tenantId}/v2.0/.well-known/openid-configuration";
        
        // Configure HTTPS requirement
        options.RequireHttpsMetadata = true;
        
        // Configure sign-out for CIAM
        //options.SignedOutRedirectUri = "/";
        options.SignedOutCallbackPath = "/signout-callback-oidc";
        options.UseTokenLifetime = false; // Don't use token lifetime
        options.SaveTokens = true; // Save tokens to access them later
        
        // Configure CIAM-specific options
        options.ResponseType = "code";
        options.ResponseMode = "form_post";
        options.UsePkce = true;
        
        // Configure cookie options
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        
        // Configure prompt behavior for password reset
        options.Prompt = "select_account"; // Changed from "login consent" to allow password reset flow
        
        // Add required scopes
        options.Scope.Clear(); // Clear existing scopes to avoid duplicates
        options.Scope.Add("openid");
        options.Scope.Add("offline_access");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("User.Read");
        // options.Scope.Add("User.ReadWrite");
        options.Scope.Add("User.ReadWrite.All");
        options.Scope.Add("Directory.AccessAsUser.All");
        // options.Scope.Add("Directory.ReadWrite.All");
        
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                // Always prompt for login
                context.ProtocolMessage.Prompt = "login";
                context.ProtocolMessage.RedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signin-oidc";
                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                context.ProtocolMessage.PostLogoutRedirectUri = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/signout-callback-oidc";
                context.ProtocolMessage.State = Guid.NewGuid().ToString();
                return Task.CompletedTask;
            },
            OnSignedOutCallbackRedirect = async context =>
            {
                // Clear session and cookies
                context.HttpContext.Session.Clear();
                await context.HttpContext.Session.LoadAsync();

                var cookieOptions = new CookieOptions
                {
                   // Path = "/",
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddYears(-1)
                };

                // Clear all cookies including MSAL cookies
                var cookiesToClear = new[] {
                    ".AspNetCore.Cookies",
                    ".AspNetCore.OpenIdConnect.Nonce",
                    ".AspNetCore.OpenIdConnect.Correlation",
                    "OIDCDemoApp.Session",
                    "msal.client.info",
                    "msal.error",
                    "msal.error.description",
                    "msal.session.state",
                    "msal.nonce.idtoken"
                };

                foreach (var cookie in cookiesToClear)
                {
                    context.HttpContext.Response.Cookies.Delete(cookie, cookieOptions);
                }

                // Set cache control headers
                context.HttpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0";
                context.HttpContext.Response.Headers["Pragma"] = "no-cache";
                context.HttpContext.Response.Headers["Expires"] = "-1";

                context.Response.Redirect("/");
                context.HandleResponse();
            },
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.Message.Contains("MFA"))
                {
                    // Handle MFA failure
                    context.HandleResponse();
                    context.Response.Redirect("/Home/MfaRequired");
                }
                return Task.CompletedTask;
            }
        };
    })
    .EnableTokenAcquisitionToCallDownstreamApi(new string[] { 
        "User.Read",
        "User.ReadWrite.All",
        "User.ReadBasic.All",
    })
    .AddInMemoryTokenCaches();

// Add cookie policy
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = SameSiteMode.Lax;
    options.Secure = CookieSecurePolicy.Always;
});

builder.Services.Configure<GraphServicePrincipalOptions>(
    builder.Configuration.GetSection("GraphServicePrincipal"));

// Add Graph API client with custom configuration
builder.Services.AddScoped(sp =>
{
    var tokenAcquisition = sp.GetRequiredService<ITokenAcquisition>();
    var authProvider = new SimpleAuthProvider(tokenAcquisition);
    var graphClient = new GraphServiceClient(authProvider, "https://graph.microsoft.com/v1.0");
    
    // Configure the client
    graphClient.RequestAdapter.BaseUrl = "https://graph.microsoft.com/v1.0";
    
    return graphClient;
});

// Add authorization
builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = options.DefaultPolicy;
});

// Add HTTPS configuration
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(listenOptions =>
    {
        listenOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
    });
});

//// Configure HTTPS
//builder.Services.AddHttpsRedirection(options =>
//{
 //   options.HttpsPort = 443;
//});
// Add Microsoft Identity Web UI
builder.Services.AddRazorPages()
    .AddMicrosoftIdentityUI();

var app = builder.Build();

// Configure the HTTP request pipeline.
//if (!app.Environment.IsDevelopment())
//{
    //app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    //app.UseHsts();
//}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Add session middleware
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();

// Simple authentication provider for Graph API
public class SimpleAuthProvider : IAuthenticationProvider
{
    private readonly ITokenAcquisition _tokenAcquisition;

    public SimpleAuthProvider(ITokenAcquisition tokenAcquisition)
    {
        _tokenAcquisition = tokenAcquisition;
    }

    public async Task AuthenticateRequestAsync(RequestInformation request, Dictionary<string, object>? additionalAuthenticationContext = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await _tokenAcquisition.GetAccessTokenForUserAsync(new[] { 
                "User.Read",
                "User.ReadWrite.All",
                "User.ReadBasic.All",
                // "User.ReadWrite",
                "Directory.AccessAsUser.All",
                // "Directory.ReadWrite.All"
            });
            
            request.Headers.Add("Authorization", $"Bearer {token}");
            request.Headers.Add("Content-Type", "application/json");
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to get access token", ex);
        }
    }


    public async Task<string> GetAppOnlyTokenAsync(GraphServicePrincipalOptions options)
    {
        var app = ConfidentialClientApplicationBuilder.Create(options.ClientId)
            .WithClientSecret(options.ClientSecret)
            .WithAuthority($"https://login.microsoftonline.com/{options.TenantId}")
            .Build();

        string[] scopes = new[] { "https://graph.microsoft.com/.default" };
        var result = await app.AcquireTokenForClient(scopes).ExecuteAsync();
        return result.AccessToken;
    }
}



using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Identity.Web;
using OIDCDemoApp.Models;
using System.Diagnostics;
using System.Text.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Security.Claims;
using Azure.Identity;
using Microsoft.Kiota.Abstractions.Authentication;
using Microsoft.Kiota.Abstractions;
using System.ComponentModel.DataAnnotations;
using static OIDCDemoApp.Models.UserProfile;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using System.Threading.Tasks;
namespace OIDCDemoApp.Controllers;

public class HomeController : Controller
{
    private readonly IOptions<AzureAdOptions> _spnOptions;
    private readonly GraphServiceClient _graphClient;
    private readonly ILogger<HomeController> _logger;
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ITokenAcquisition _tokenAcquisition;
    private static readonly Dictionary<string, (int Count, DateTime LastAttempt)> _loginAttempts = new();
    private const int MaxLoginAttempts = 5;
    private const int LoginAttemptWindowMinutes = 15;

    public HomeController(
        GraphServiceClient graphClient,
        ILogger<HomeController> logger,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        ITokenAcquisition tokenAcquisition,
        IOptions<AzureAdOptions> spnOptions)
    {
        _graphClient = graphClient;
        _logger = logger;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _tokenAcquisition = tokenAcquisition;
        _spnOptions = spnOptions;
    }

    private void AddSecurityHeaders()
    {
        // Add security headers
        Response.Headers.Add("X-Content-Type-Options", "nosniff");
        Response.Headers.Add("X-Frame-Options", "DENY");
        Response.Headers.Add("X-XSS-Protection", "1; mode=block");
        Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
        Response.Headers.Add("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';");
        Response.Headers.Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        Response.Headers.Add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        Response.Headers.Add("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        Response.Headers.Add("Pragma", "no-cache");
        Response.Headers.Add("Expires", "0");
    }

    private bool IsRateLimited(string key)
    {
        if (_loginAttempts.TryGetValue(key, out var attempt))
        {
            if (DateTime.UtcNow - attempt.LastAttempt < TimeSpan.FromMinutes(LoginAttemptWindowMinutes))
            {
                if (attempt.Count >= MaxLoginAttempts)
                {
                    _logger.LogWarning("Rate limit exceeded for key: {Key}", key);
                    return true;
                }
            }
            else
            {
                _loginAttempts.Remove(key);
            }
        }
        return false;
    }

    private void IncrementAttemptCount(string key)
    {
        if (_loginAttempts.TryGetValue(key, out var attempt))
        {
            if (DateTime.UtcNow - attempt.LastAttempt < TimeSpan.FromMinutes(LoginAttemptWindowMinutes))
            {
                _loginAttempts[key] = (attempt.Count + 1, DateTime.UtcNow);
            }
            else
            {
                _loginAttempts[key] = (1, DateTime.UtcNow);
            }
        }
        else
        {
            _loginAttempts[key] = (1, DateTime.UtcNow);
        }
    }

    private void LogSecurityEvent(string eventType, string details, string userId = null)
    {
        var logEntry = new
        {
            Timestamp = DateTime.UtcNow,
            EventType = eventType,
            Details = details,
            UserId = userId,
            IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"].ToString()
        };

        _logger.LogInformation("Security Event: {@LogEntry}", logEntry);
    }

    public IActionResult Index()
    {
        AddSecurityHeaders();
        return View();
    }

    [Authorize]
    public async Task<IActionResult> Profile()
    {
        AddSecurityHeaders();
        try
        {
            // Get the current user's email from claims
            var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                       ?? User.FindFirst("preferred_username")?.Value
                       ?? User.FindFirst("email")?.Value;

            if (string.IsNullOrEmpty(email))
            {
                _logger.LogWarning("Failed to get current user email from claims");
                return Error("Failed to retrieve user email from authentication claims");
            }

            _logger.LogInformation("Retrieving user profile for email: {Email}", email);

            // Get app-only token using SPN for the wrapper API
            var spnOptions = _spnOptions.Value;
            var token = await GraphTokenHelper.GetAppOnlyTokenAsync(spnOptions);

            // Create HTTP client for wrapper API call
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Build the wrapper API URL
            var apiUrl = $"https://b2crestapi-hydyhbdweeasb5bj.westeurope-01.azurewebsites.net/Graph/getUserByEmail?email={Uri.EscapeDataString(email)}";

            _logger.LogInformation("Calling wrapper API: {ApiUrl}", apiUrl);

            // Make GET request to wrapper API
            var response = await httpClient.GetAsync(apiUrl);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("Wrapper API response: {StatusCode}, Content length: {ContentLength}",
                response.StatusCode, responseContent?.Length ?? 0);

            if (response.IsSuccessStatusCode)
            {
                // Parse the JSON response
                JsonElement userData;
                try
                {
                    userData = System.Text.Json.JsonSerializer.Deserialize<JsonElement>(responseContent);
                }
                catch (System.Text.Json.JsonException ex)
                {
                    _logger.LogError(ex, "Failed to parse JSON response from wrapper API. Content: {Content}", responseContent);
                    return Error("Failed to parse response from wrapper API");
                }

                // Create user profile from wrapper API data
                var userProfile = new UserProfile
                {
                    Name = GetJsonPropertyValue(userData, "displayName") ?? GetJsonPropertyValue(userData, "name"),
                    Email = GetJsonPropertyValue(userData, "mail") ?? GetJsonPropertyValue(userData, "userPrincipalName") ?? email,
                    ObjectId = GetJsonPropertyValue(userData, "id") ?? GetJsonPropertyValue(userData, "objectId"),
                    GivenName = GetJsonPropertyValue(userData, "givenName"),
                    Surname = GetJsonPropertyValue(userData, "surname"),
                    StreetAddress = GetJsonPropertyValue(userData, "streetAddress"),
                    City = GetJsonPropertyValue(userData, "city"),
                    StateProvince = GetJsonPropertyValue(userData, "state"),
                    CountryOrRegion = GetJsonPropertyValue(userData, "country")
                };

                _logger.LogInformation("Successfully retrieved user profile from wrapper API: {DisplayName}", userProfile.Name);

                // Get updated fields from TempData if available
                if (TempData["UpdatedFields"] != null)
                {
                    var updatedFields = System.Text.Json.JsonSerializer.Deserialize<List<string>>(TempData["UpdatedFields"].ToString());
                    userProfile.UpdatedFields = updatedFields;
                }

                return View(userProfile);
            }
            else
            {
                _logger.LogError("Wrapper API returned error. Status: {StatusCode}, Content: {Content}",
                    response.StatusCode, responseContent);

                var errorMessage = "Failed to retrieve user profile from wrapper API.";
                try
                {
                    var error = System.Text.Json.JsonSerializer.Deserialize<GraphError>(responseContent);
                    if (error?.Error != null)
                    {
                        errorMessage = $"Wrapper API Error: {error.Error.Message}";
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error parsing wrapper API error response");
                }

                return Error(errorMessage);
            }
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP request exception when calling wrapper API");
            return Error($"Failed to connect to wrapper API: {ex.Message}");
        }
        catch (System.Text.Json.JsonException ex)
        {
            _logger.LogError(ex, "JSON parsing exception when processing wrapper API response");
            return Error($"Failed to parse wrapper API response: {ex.Message}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in Profile action");
            return Error($"An unexpected error occurred: {ex.Message}");
        }
    }

    // Helper method to safely get JSON property values
    private string GetJsonPropertyValue(JsonElement element, string propertyName)
    {
        try
        {
            if (element.TryGetProperty(propertyName, out var property))
            {
                return property.ValueKind == JsonValueKind.Null ? null : property.GetString();
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error getting JSON property {PropertyName}", propertyName);
        }
        return null;
    }

    [Authorize]
    public async Task<IActionResult> TestGraphApi()
    {
        try
        {
            // Try to get user profile from Graph API
            var user = await _graphClient.Me.GetAsync();

            if (user == null)
            {
                _logger.LogWarning("Graph API returned null user profile");
                return Error("Failed to retrieve user profile from Graph API");
            }

            _logger.LogInformation("Successfully retrieved user profile from Graph API: {DisplayName}", user.DisplayName);

            // Create a view model with the user information
            var viewModel = new
            {
                DisplayName = user.DisplayName ?? "Not available",
                UserPrincipalName = user.UserPrincipalName ?? "Not available",
                Id = user.Id ?? "Not available",
                Mail = user.Mail ?? "Not available",
                JobTitle = user.JobTitle ?? "Not available",
                Department = user.Department ?? "Not available"
            };

            return View("Index", viewModel);
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Graph API Service Exception");
            var errorMessage = $"Graph API Error: {ex.Message}";
            if (ex.ResponseHeaders != null)
            {
                errorMessage += $"\nResponse Headers: {string.Join(", ", ex.ResponseHeaders.Select(h => $"{h.Key}={h.Value}"))}";
            }
            return Error(errorMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error accessing Graph API");
            return Error($"Error accessing Graph API: {ex.Message}");
        }
    }

    public async Task<IActionResult> CheckOpenIdConfig()
    {
        try
        {
            var httpClient = _httpClientFactory.CreateClient();
            var authority = _configuration["AzureAd:Instance"];
            var domain = _configuration["AzureAd:Domain"];

            // Try different OpenID configuration URLs
            var configUrls = new[]
            {
                $"{authority}/{domain}/.well-known/openid-configuration",
                $"{authority}/{domain}/v2.0/.well-known/openid-configuration"
            };

            var results = new List<object>();

            foreach (var url in configUrls)
            {
                try
                {
                    var response = await httpClient.GetAsync(url);
                    results.Add(new
                    {
                        Url = url,
                        StatusCode = response.StatusCode,
                        Content = await response.Content.ReadAsStringAsync()
                    });
                }
                catch (Exception ex)
                {
                    results.Add(new
                    {
                        Url = url,
                        Error = ex.Message
                    });
                }
            }

            return View("OpenIdConfig", results);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking OpenID configuration");
            return Error($"Error checking OpenID configuration: {ex.Message}");
        }
    }

    public async Task<IActionResult> Diagnostic()
    {
        try
        {
            var diagnosticInfo = new DiagnosticViewModel
            {
                IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                UserClaims = User.Claims.Select(c => new UserClaim { Type = c.Type, Value = c.Value }).ToList(),
                Configuration = new ConfigurationInfo
                {
                    Authority = _configuration["AzureAd:Instance"],
                    Domain = _configuration["AzureAd:Domain"],
                    ClientId = _configuration["AzureAd:ClientId"],
                    CallbackPath = _configuration["AzureAd:CallbackPath"],
                    SignedOutCallbackPath = _configuration["AzureAd:SignedOutCallbackPath"]
                },
                GraphApiStatus = "Not authenticated"
            };

            if (User.Identity?.IsAuthenticated == true)
            {
                try
                {
                    // Test Graph API connection
                    var user = await _graphClient.Me.GetAsync();
                    diagnosticInfo.GraphApiStatus = "Connected successfully";
                    diagnosticInfo.UserInfo = new UserInfo
                    {
                        DisplayName = user.DisplayName,
                        UserPrincipalName = user.UserPrincipalName,
                        Id = user.Id
                    };
                }
                catch (Exception ex)
                {
                    diagnosticInfo.GraphApiStatus = $"Error: {ex.Message}";
                }
            }

            return View(diagnosticInfo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in diagnostic endpoint");
            return Error($"Error in diagnostic endpoint: {ex.Message}");
        }
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [Authorize]
    public async Task<IActionResult> SignOut()
    {
        try
        {
            // Get the current user's account
            var user = await _graphClient.Me.GetAsync();
            if (user != null)
            {
                _logger.LogInformation("User {DisplayName} signing out", user.DisplayName);

                try
                {
                    // Revoke all refresh tokens for the user
                    await _graphClient.Users[user.Id].RevokeSignInSessions.PostAsync();
                    _logger.LogInformation("Successfully revoked sign-in sessions for user {DisplayName}", user.DisplayName);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to revoke Graph API sessions for user {DisplayName}", user.DisplayName);
                }
            }

            // Clear all cookies with specific options
            var cookieOptions = new CookieOptions
            {
                Path = "/",
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.UtcNow.AddYears(-1) // Expire in the past
            };

            // Clear all cookies including authentication cookies
            foreach (var cookie in Request.Cookies.Keys)
            {
                Response.Cookies.Delete(cookie, cookieOptions);
            }

            // Clear specific authentication cookies
            var authCookies = new[] {
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

            foreach (var cookie in authCookies)
            {
                Response.Cookies.Delete(cookie, cookieOptions);
            }

            // Clear the session
            HttpContext.Session.Clear();
            await HttpContext.Session.LoadAsync();

            // Clear browser cache by setting cache control headers
            Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0";
            Response.Headers["Pragma"] = "no-cache";
            Response.Headers["Expires"] = "-1";

            // Sign out from OpenID Connect with specific options
            var authProperties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("Index", "Home"),
                AllowRefresh = false,
                IsPersistent = false
            };

            // Sign out from both authentication schemes
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, authProperties);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme, authProperties);

            // Redirect to home page with cache-busting parameters
            return RedirectToAction("Index", "Home", new { t = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during sign-out");
            // Even if there's an error, try to sign out locally
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Clear();
            return RedirectToAction("Index", "Home");
        }
    }

    [Authorize]
    public async Task<IActionResult> EditProfile()
    {
        try
        {
            // Get the current user's email from claims
            var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                       ?? User.FindFirst("preferred_username")?.Value
                       ?? User.FindFirst("email")?.Value;

            if (string.IsNullOrEmpty(email))
            {
                _logger.LogWarning("Failed to get current user email from claims");
                return Error("Failed to retrieve user email from authentication claims");
            }

            _logger.LogInformation("Retrieving user profile for editing - email: {Email}", email);

            // Get app-only token using SPN for the wrapper API
            var spnOptions = _spnOptions.Value;
            var token = await GraphTokenHelper.GetAppOnlyTokenAsync(spnOptions);

            // Create HTTP client for wrapper API call
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Build the wrapper API URL for getting user by email
            var apiUrl = $"https://b2crestapi-hydyhbdweeasb5bj.westeurope-01.azurewebsites.net/Graph/getUserByEmail?email={Uri.EscapeDataString(email)}";

            _logger.LogInformation("Calling wrapper API for edit profile: {ApiUrl}", apiUrl);

            // Make GET request to wrapper API
            var response = await httpClient.GetAsync(apiUrl);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("Wrapper API response for edit profile: {StatusCode}, Content length: {ContentLength}",
                response.StatusCode, responseContent?.Length ?? 0);

            if (response.IsSuccessStatusCode)
            {
                // Parse the JSON response
                JsonElement userData;
                try
                {
                    userData = System.Text.Json.JsonSerializer.Deserialize<JsonElement>(responseContent);
                }
                catch (System.Text.Json.JsonException ex)
                {
                    _logger.LogError(ex, "Failed to parse JSON response from wrapper API for edit profile. Content: {Content}", responseContent);
                    return Error("Failed to parse response from wrapper API");
                }

                // Create user profile from wrapper API data
                var userProfile = new UserProfile
                {
                    Name = GetJsonPropertyValue(userData, "displayName") ?? GetJsonPropertyValue(userData, "name"),
                    Email = GetJsonPropertyValue(userData, "mail") ?? GetJsonPropertyValue(userData, "userPrincipalName") ?? email,
                    ObjectId = GetJsonPropertyValue(userData, "id") ?? GetJsonPropertyValue(userData, "objectId"),
                    GivenName = GetJsonPropertyValue(userData, "givenName"),
                    Surname = GetJsonPropertyValue(userData, "surname"),
                    StreetAddress = GetJsonPropertyValue(userData, "streetAddress"),
                    City = GetJsonPropertyValue(userData, "city"),
                    StateProvince = GetJsonPropertyValue(userData, "state"),
                    CountryOrRegion = GetJsonPropertyValue(userData, "country")
                };

                _logger.LogInformation("Successfully retrieved user profile from wrapper API for editing: {DisplayName}", userProfile.Name);

                return View(userProfile);
            }
            else
            {
                _logger.LogError("Wrapper API returned error for edit profile. Status: {StatusCode}, Content: {Content}",
                    response.StatusCode, responseContent);

                var errorMessage = "Failed to retrieve user profile from wrapper API.";
                try
                {
                    var error = System.Text.Json.JsonSerializer.Deserialize<GraphError>(responseContent);
                    if (error?.Error != null)
                    {
                        errorMessage = $"Wrapper API Error: {error.Error.Message}";
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error parsing wrapper API error response for edit profile");
                }

                return Error(errorMessage);
            }
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP request exception when calling wrapper API for edit profile");
            return Error($"Failed to connect to wrapper API: {ex.Message}");
        }
        catch (System.Text.Json.JsonException ex)
        {
            _logger.LogError(ex, "JSON parsing exception when processing wrapper API response for edit profile");
            return Error($"Failed to parse wrapper API response: {ex.Message}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in EditProfile action");
            return Error($"An unexpected error occurred: {ex.Message}");
        }
    }

    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateProfile(UserProfile model)
    {
        try
        {
            _logger.LogInformation("Starting profile update for user");
            _logger.LogInformation("Model data: {@ModelData}", model);

            // Clear any existing model state errors
            ModelState.Clear();

            // Validate only required fields
            if (string.IsNullOrWhiteSpace(model.Name))
            {
                ModelState.AddModelError("Name", "Display Name is required");
            }

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Model state is invalid: {@ModelState}", ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage));
                return View("EditProfile", model);
            }

            // Get the current user's email from claims
            var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                       ?? User.FindFirst("preferred_username")?.Value
                       ?? User.FindFirst("email")?.Value;

            if (string.IsNullOrEmpty(email))
            {
                _logger.LogError("Failed to get current user email from claims");
                return Error("Failed to get current user information");
            }

            // Get app-only token using SPN for the wrapper API
            var spnOptions = _spnOptions.Value;
            var token = await GraphTokenHelper.GetAppOnlyTokenAsync(spnOptions);

            // Create update user object matching the wrapper API format
            var updates = new Dictionary<string, object>
            {
                ["displayName"] = model.Name,
                ["givenName"] = model.GivenName,
                ["surname"] = model.Surname,
                ["streetAddress"] = model.StreetAddress,
                ["city"] = model.City,
                ["state"] = model.StateProvince,
                ["country"] = model.CountryOrRegion
            };

            // Log the update request
            _logger.LogInformation("Preparing update request with data: {@UpdateData}", updates);

            // Convert to JSON
            var jsonContent = System.Text.Json.JsonSerializer.Serialize(updates);

            // Create HTTP content
            var content = new StringContent(
                jsonContent,
                System.Text.Encoding.UTF8,
                "application/json"
            );

            // Create HTTP client for wrapper API call
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Build the wrapper API URL for updating user by email
            var apiUrl = $"https://b2crestapi-hydyhbdweeasb5bj.westeurope-01.azurewebsites.net/Graph/updateUserByEmail?email={Uri.EscapeDataString(email)}";

            _logger.LogInformation("Calling wrapper API for profile update: {ApiUrl}", apiUrl);

            // Make PATCH request to wrapper API
            var request = new HttpRequestMessage(new HttpMethod("PATCH"), apiUrl)
            {
                Content = content
            };
            var response = await httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("Wrapper API response for profile update: {StatusCode}, Content length: {ContentLength}",
                response.StatusCode, responseContent?.Length ?? 0);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Successfully updated profile using wrapper API");

                // Store success message in TempData
                TempData["SuccessMessage"] = "Profile updated successfully!";

                // Redirect to Profile action
                return RedirectToAction("Profile");
            }
            else
            {
                _logger.LogError("Failed to update profile via wrapper API. Status: {StatusCode}, Content: {Content}",
                    response.StatusCode, responseContent);

                var errorMessage = "Failed to update profile.";
                try
                {
                    var error = System.Text.Json.JsonSerializer.Deserialize<GraphError>(responseContent);
                    if (error?.Error != null)
                    {
                        errorMessage = $"Wrapper API Error: {error.Error.Message}";
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error parsing wrapper API error response for profile update");
                }

                ModelState.AddModelError("", errorMessage);
                return View("EditProfile", model);
            }
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP request exception when calling wrapper API for profile update");
            ModelState.AddModelError("", $"Failed to connect to wrapper API: {ex.Message}");
            return View("EditProfile", model);
        }
        catch (System.Text.Json.JsonException ex)
        {
            _logger.LogError(ex, "JSON parsing exception when processing wrapper API response for profile update");
            ModelState.AddModelError("", $"Failed to parse wrapper API response: {ex.Message}");
            return View("EditProfile", model);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in UpdateProfile action: {Message}", ex.Message);
            ModelState.AddModelError("", "An unexpected error occurred. Please try again.");
            return View("EditProfile", model);
        }
    }
    // Helper class for Graph API error responses
    private class GraphError
    {
        public GraphErrorDetail Error { get; set; }
    }

    private class GraphErrorDetail
    {
        public string Code { get; set; }
        public string Message { get; set; }
        public string InnerError { get; set; }
    }

[Authorize]
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> DeleteProfile()
{
    try
    {
        // Get the current user's email from claims
        var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                   ?? User.FindFirst("preferred_username")?.Value
                   ?? User.FindFirst("email")?.Value;

        if (string.IsNullOrEmpty(email))
        {
            _logger.LogError("Failed to get current user email from claims");
            TempData["Error"] = "Failed to get user information. Please try again.";
            return RedirectToAction(nameof(Profile));
        }

        // Get app-only token using SPN for the wrapper API
        var spnOptions = _spnOptions.Value;
        var token = await GraphTokenHelper.GetAppOnlyTokenAsync(spnOptions);

        // Create HTTP client for wrapper API call
        using var httpClient = _httpClientFactory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // Build the wrapper API URL for deleting user by email
        var apiUrl = $"https://b2crestapi-hydyhbdweeasb5bj.westeurope-01.azurewebsites.net/Graph/deleteUserByEmail?email={Uri.EscapeDataString(email)}";

        _logger.LogInformation("Calling wrapper API for delete profile: {ApiUrl}", apiUrl);

        // Make DELETE request to wrapper API
        var response = await httpClient.DeleteAsync(apiUrl);
        var responseContent = await response.Content.ReadAsStringAsync();

        _logger.LogInformation("Wrapper API response for delete profile: {StatusCode}, Content length: {ContentLength}",
            response.StatusCode, responseContent?.Length ?? 0);

        if (response.IsSuccessStatusCode)
        {
            _logger.LogInformation("User with email {Email} was successfully deleted", email);

            // Sign out the user after deletion
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

            // Clear session
            HttpContext.Session.Clear();

            return RedirectToAction("Index", "Home");
        }
        else
        {
            _logger.LogError("Failed to delete user via wrapper API. Status: {StatusCode}, Content: {Content}",
                response.StatusCode, responseContent);

            string errorMessage = "Failed to delete account.";
            try
            {
                var error = System.Text.Json.JsonSerializer.Deserialize<GraphError>(responseContent);
                if (error?.Error != null)
                {
                    errorMessage = error.Error.Message;
                    if (error.Error.Code == "Authorization_RequestDenied")
                    {
                        errorMessage = "You don't have permission to delete the account. Please contact your administrator.";
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing wrapper API error response for delete profile");
            }
            TempData["Error"] = errorMessage;
            return RedirectToAction(nameof(Profile));
        }
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error deleting user profile via wrapper API");
        TempData["Error"] = "An unexpected error occurred. Please try again later.";
        return RedirectToAction(nameof(Profile));
    }
}

    private async Task<GraphServiceClient> GetGraphClient()
    {
        try
        {
            // Get the access token
            string accessToken = await _tokenAcquisition.GetAccessTokenForUserAsync(
                new[] {
                    "User.Read",
                    "User.ReadWrite.All",
                    "User.ReadBasic.All"
                });

            // Create a new GraphServiceClient with the token
            var authProvider = new SimpleAuthProvider(accessToken);
            return new GraphServiceClient(authProvider);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting Graph client");
            throw;
        }
    }

    private class SimpleAuthProvider : IAuthenticationProvider
    {
        private readonly string _token;

        public SimpleAuthProvider(string token)
        {
            _token = token;
        }

        public Task AuthenticateRequestAsync(RequestInformation request, Dictionary<string, object>? additionalAuthenticationContext = null, CancellationToken cancellationToken = default)
        {
            request.Headers.Add("Authorization", $"Bearer {_token}");
            return Task.CompletedTask;
        }
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error(string message = null)
    {
        var errorViewModel = new ErrorViewModel
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
            ErrorMessage = message
        };
        return View(errorViewModel);
    }

    [Authorize]
    public async Task<IActionResult> CheckMfaStatus()
    {
        try
        {
            var graphClient = await GetGraphClient();
            var user = await graphClient.Me.GetAsync();

            // Get authentication methods
            var authMethods = await graphClient.Users[user.Id]
                .Authentication.Methods.GetAsync();

            var mfaStatus = new
            {
                IsMfaEnabled = authMethods?.Value?.Any(m => m.GetType().Name.Contains("MicrosoftAuthenticator")) ?? false,
                AvailableMethods = authMethods?.Value?.Select(m => new
                {
                    MethodType = GetMethodTypeDisplayName(m.GetType().Name),
                    MethodId = m.Id,
                    IsEnabled = true, // Since we can get the method, it's enabled
                    LastUsed = GetLastUsedDate(m) // Add last used date if available
                }).ToList(),
                UserId = user.Id,
                UserPrincipalName = user.UserPrincipalName
            };

            return View(mfaStatus);
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Graph API Service Exception while checking MFA status");
            return Error($"Error checking MFA status: {ex.Message}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking MFA status");
            return Error($"Error checking MFA status: {ex.Message}");
        }
    }

    private string GetMethodTypeDisplayName(string typeName)
    {
        return typeName switch
        {
            var name when name.Contains("MicrosoftAuthenticator") => "Microsoft Authenticator App",
            var name when name.Contains("Phone") => "Phone Authentication",
            var name when name.Contains("Email") => "Email Authentication",
            var name when name.Contains("Fido") => "FIDO2 Security Key",
            var name when name.Contains("WindowsHello") => "Windows Hello",
            _ => typeName
        };
    }

    private string GetLastUsedDate(AuthenticationMethod method)
    {
        // Try to get the last used date if available
        try
        {
            var lastUsedProperty = method.GetType().GetProperty("LastUsedDateTime");
            if (lastUsedProperty != null)
            {
                var lastUsed = lastUsedProperty.GetValue(method);
                if (lastUsed != null)
                {
                    return ((DateTimeOffset)lastUsed).ToString("g");
                }
            }
        }
        catch
        {
            // If we can't get the last used date, return "Unknown"
        }
        return "Unknown";
    }

    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(string NewPassword, string ConfirmPassword)
    {
        try
        {
            _logger.LogInformation("Starting password reset process");

            // Validate inputs
            if (string.IsNullOrEmpty(NewPassword) || string.IsNullOrEmpty(ConfirmPassword))
            {
                TempData["Error"] = "All password fields are required.";
                return RedirectToAction(nameof(Profile));
            }

            if (NewPassword != ConfirmPassword)
            {
                TempData["Error"] = "New password and confirmation password do not match.";
                return RedirectToAction(nameof(Profile));
            }

            // Validate password complexity
            if (!IsPasswordComplex(NewPassword))
            {
                TempData["Error"] = "New password does not meet complexity requirements.";
                return RedirectToAction(nameof(Profile));
            }

            // Get the current user's email from claims (or however you store it)
            var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                _logger.LogError("Failed to get current user email from claims");
                TempData["Error"] = "Failed to get user information. Please try again.";
                return RedirectToAction(nameof(Profile));
            }

            // Get the app-only token using SPN (as in other admin-style APIs)
            var spnOptions = _spnOptions.Value;
            var accessToken = await GraphTokenHelper.GetAppOnlyTokenAsync(spnOptions);

            // Build the wrapper API URL using the new endpoint format
            var apiUrl = $"https://b2crestapi-hydyhbdweeasb5bj.westeurope-01.azurewebsites.net/Graph/resetPasswordByEmail?email={Uri.EscapeDataString(email)}";
            
            // Prepare the payload as expected by the new API format
            var resetPasswordRequest = new
            {
                newPassword = NewPassword,
                //forceChangePasswordNextSignIn = false,
                //forceChangePasswordNextSignInWithMfa = false
            };

            var jsonContent = JsonSerializer.Serialize(resetPasswordRequest);
            var content = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");

            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

            // Make the PATCH request to the wrapper API
            var request = new HttpRequestMessage(new HttpMethod("PATCH"), apiUrl)
            {
                Content = content
            };
            var response = await httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogInformation($"Password reset response: {response.StatusCode}");
            _logger.LogInformation($"Response content: {responseContent}");

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Password successfully changed for user {Email}", email);
                TempData["SuccessMessage"] = "Your password has been successfully changed. Please sign in with your new password.";
                return RedirectToAction(nameof(Profile));
            }
            else
            {
                _logger.LogError("Failed to change password. Status: {StatusCode}, Content: {Content}",
                    response.StatusCode, responseContent);

                string errorMessage = "Failed to change password.";
                try
                {
                    var error = JsonSerializer.Deserialize<GraphError>(responseContent);
                    if (error?.Error != null)
                    {
                        errorMessage = error.Error.Message;
                        if (error.Error.Code == "Authorization_RequestDenied")
                        {
                            errorMessage = "You don't have permission to change the password. Please contact your administrator.";
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error parsing wrapper API error response");
                }

                TempData["Error"] = errorMessage;
                return RedirectToAction(nameof(Profile));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in ResetPassword action");
            TempData["Error"] = "An unexpected error occurred while changing your password. Please try again.";
            return RedirectToAction(nameof(Profile));
        }
    }

    private bool IsPasswordComplex(string password)
    {
        // Password complexity requirements for Azure Entra External ID
        var hasMinLength = password.Length >= 8;
        var hasUpperCase = password.Any(char.IsUpper);
        var hasLowerCase = password.Any(char.IsLower);
        var hasDigit = password.Any(char.IsDigit);
        var hasSpecialChar = password.Any(c => !char.IsLetterOrDigit(c));

        return hasMinLength && hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
    }

    public static class GraphTokenHelper
    {
        public static async Task<string> GetAppOnlyTokenAsync(UserProfile.AzureAdOptions options)
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
}


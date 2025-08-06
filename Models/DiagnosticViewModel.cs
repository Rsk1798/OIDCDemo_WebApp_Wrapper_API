using System.Collections.Generic;

namespace OIDCDemoApp.Models;

public class DiagnosticViewModel
{
    public bool IsAuthenticated { get; set; }
    public List<UserClaim> UserClaims { get; set; } = new();
    public ConfigurationInfo Configuration { get; set; } = new();
    public string GraphApiStatus { get; set; }
    public UserInfo UserInfo { get; set; }
}

public class UserClaim
{
    public string Type { get; set; }
    public string Value { get; set; }
}

public class ConfigurationInfo
{
    public string Authority { get; set; }
    public string Domain { get; set; }
    public string ClientId { get; set; }
    public string PolicyId { get; set; }
    public string CallbackPath { get; set; }
    public string SignedOutCallbackPath { get; set; }
}

public class UserInfo
{
    public string DisplayName { get; set; }
    public string UserPrincipalName { get; set; }
    public string Id { get; set; }
} 
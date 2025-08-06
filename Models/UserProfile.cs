using System.Security.Claims;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;

namespace OIDCDemoApp.Models
{
    public class UserProfile
    {
        [Required(ErrorMessage = "Display Name is required")]
        [Display(Name = "Display Name")]
        public string Name { get; set; }

        [Display(Name = "Email")]
        public string Email { get; set; }

        [Display(Name = "Object ID")]
        public string ObjectId { get; set; }

        [Display(Name = "Given Name")]
        public string GivenName { get; set; }

        [Display(Name = "Surname")]
        public string Surname { get; set; }

        [Display(Name = "Street Address")]
        public string StreetAddress { get; set; }

        [Display(Name = "City")]
        public string City { get; set; }

        [Display(Name = "State/Province")]
        public string StateProvince { get; set; }

        [Display(Name = "Country/Region")]
        public string CountryOrRegion { get; set; }

        public List<string> UpdatedFields { get; set; } = new List<string>();

        public static UserProfile FromClaimsPrincipal(ClaimsPrincipal user)
        {
            return new UserProfile
            {
                Name = user.FindFirst("name")?.Value,
                Email = user.FindFirst("preferred_username")?.Value,
                ObjectId = user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value,
                GivenName = user.FindFirst("given_name")?.Value,
                Surname = user.FindFirst("family_name")?.Value
            };
        }

        public class GraphServicePrincipalOptions
        {
            public string TenantId { get; set; }
            public string ClientId { get; set; }
            public string ClientSecret { get; set; }
        }
    }
} 
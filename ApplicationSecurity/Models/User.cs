using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace ApplicationSecurity.Models
{
    public class User : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }

        [Required]
        public string? MobileNo { get; set; }

        [Required]
        public string? BillingAddress { get; set; }

        [Required]
        public string? ShippingAddress { get; set; }

        [Required]
        public string? CreditCardNo { get; set; } 

        public string? ProfilePictureUrl { get; set; }
    }
}
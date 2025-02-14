using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using System.Net;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using System;
using ApplicationSecurity.Models;
using ApplicationSecurity.Services;

namespace ApplicationSecurity.Pages.Account
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IWebHostEnvironment _environment;

        public RegisterModel(UserManager<User> userManager, SignInManager<User> signInManager, IWebHostEnvironment environment)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _environment = environment;
        }

        [BindProperty]
        public RegisterInputModel Input { get; set; }

        public class RegisterInputModel
        {
            [Required]
            public string FirstName { get; set; }

            [Required]
            public string LastName { get; set; }

            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            public string MobileNo { get; set; }

            [Required]
            public string BillingAddress { get; set; }

            [Required]
            public string ShippingAddress { get; set; }

            [Required]
            [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card number must be exactly 16 digits.")]
            public string CreditCardNo { get; set; } // Must be exactly 16 digits

            [Required]
            [DataType(DataType.Password)]
            [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters long.")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$",
                ErrorMessage = "Password must contain an uppercase letter, lowercase letter, number, and special character.")]
            public string Password { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Compare("Password", ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; }

            [Required]
            public IFormFile ProfilePicture { get; set; } // JPG only
        }


        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var sanitizedEmail = WebUtility.HtmlEncode(Input.Email);

            // Check if email is already taken
            var existingUser = await _userManager.FindByEmailAsync(sanitizedEmail);
            if (existingUser != null)
            {
                ModelState.AddModelError("Input.Email", "This email is already registered.");
                return Page();
            }

            // Validate profile picture (JPG only)
            if (Input.ProfilePicture != null && Path.GetExtension(Input.ProfilePicture.FileName).ToLower() != ".jpg")
            {
                ModelState.AddModelError(string.Empty, "Only JPG images are allowed.");
                return Page();
            }

            string uniqueFileName = $"{Guid.NewGuid()}.jpg"; // Unique filename
            string uploadPath = Path.Combine(_environment.WebRootPath, "uploads");

            // Ensure directory exists
            if (!Directory.Exists(uploadPath))
            {
                Directory.CreateDirectory(uploadPath);
            }

            string filePath = Path.Combine(uploadPath, uniqueFileName);

            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await Input.ProfilePicture.CopyToAsync(fileStream);
            }

            var encryptedCreditCard = EncryptionHelper.Encrypt(Input.CreditCardNo);

            var user = new User
            {
                FirstName = Input.FirstName,
                LastName = Input.LastName,
                Email = sanitizedEmail,
                UserName = sanitizedEmail,
                MobileNo = Input.MobileNo,
                BillingAddress = Input.BillingAddress,
                ShippingAddress = Input.ShippingAddress,
                CreditCardNo = encryptedCreditCard,
                ProfilePictureUrl = "/uploads/" + uniqueFileName // Store the correct URL path
            };

            var result = await _userManager.CreateAsync(user, Input.Password);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToPage("/Index");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }

    }
}

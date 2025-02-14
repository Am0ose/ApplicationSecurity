using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Threading.Tasks;
using ApplicationSecurity.Models;
using ApplicationSecurity.Services;

namespace ApplicationSecurity.Pages
{
    public class IndexModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public IndexModel(UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public User LoggedInUser { get; set; }
        public string MaskedCreditCard { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            if (!User.Identity.IsAuthenticated)
            {
                // Redirect to login if user is not authenticated
                return RedirectToPage("/Account/Login");
            }

            var sessionExpiryString = HttpContext.Session.GetString("SessionExpiry");

            if (!string.IsNullOrEmpty(sessionExpiryString) &&
                DateTime.TryParse(sessionExpiryString, out DateTime sessionExpiry))
            {
                if (DateTime.UtcNow > sessionExpiry)
                {
                    // Auto logout: Clear session, delete cookies, and sign out user
                    HttpContext.Session.Clear();
                    Response.Cookies.Delete(".AspNetCore.Identity.Application"); // Clear authentication cookie

                    await _signInManager.SignOutAsync(); // Sign out user
                    return RedirectToPage("/Account/Login");
                }

                // Sliding Expiration: Extend session expiry time if user is active
                sessionExpiry = DateTime.UtcNow.AddMinutes(20);
                HttpContext.Session.SetString("SessionExpiry", sessionExpiry.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            }

            

            LoggedInUser = await _userManager.GetUserAsync(User);
            // Decrypt and mask the credit card number
            if (!string.IsNullOrEmpty(LoggedInUser?.CreditCardNo))
            {
                string decryptedCreditCard = EncryptionHelper.Decrypt(LoggedInUser.CreditCardNo);

                // Mask all but the last 4 digits
                if (decryptedCreditCard.Length >= 4)
                {
                    MaskedCreditCard = "****-****-****-" + decryptedCreditCard[^4..];
                }
                else
                {
                    MaskedCreditCard = "Invalid Card"; // Fallback for corrupted data
                }
            }

            return Page();
        }
    }
}

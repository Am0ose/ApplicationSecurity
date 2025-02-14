using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;
using ApplicationSecurity.Services;
using ApplicationSecurity.Models;

namespace ApplicationSecurity.Pages.Account
{
    public class Verify2FAModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly AuditLogService _auditLogService;

        public Verify2FAModel(UserManager<User> userManager,
                              SignInManager<User> signInManager,
                              AuditLogService auditLogService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _auditLogService = auditLogService;
        }

        [BindProperty]
        public string OTP { get; set; }

        public bool OTPVerified { get; set; } = false;
        public int RemainingAttempts { get; set; }

        private const int MaxOTPAttempts = 3;
        private const int LockoutDurationMinutes = 5; // User gets locked out for 5 minutes

        public async Task<IActionResult> OnGetAsync()
        {
            RemainingAttempts = HttpContext.Session.GetInt32("2FA_Attempts") ?? MaxOTPAttempts;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var storedOTP = HttpContext.Session.GetString("2FA_OTP");
            var email = HttpContext.Session.GetString("2FA_Email");

            if (string.IsNullOrEmpty(storedOTP) || string.IsNullOrEmpty(email))
            {
                ModelState.AddModelError(string.Empty, "Session expired. Please log in again.");
                return RedirectToPage("/Account/Login");
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found.");
                return RedirectToPage("/Account/Login");
            }

            // Retrieve remaining attempts
            RemainingAttempts = HttpContext.Session.GetInt32("2FA_Attempts") ?? MaxOTPAttempts;

            if (OTP == storedOTP)
            {
                //  Successful OTP Verification
                HttpContext.Session.Remove("2FA_OTP");
                HttpContext.Session.Remove("2FA_Attempts");
                HttpContext.Session.Remove("2FA_Email");

                OTPVerified = true;
                return RedirectToPage("/Index");
            }
            else
            {
                //  Failed OTP Attempt
                RemainingAttempts--;

                if (RemainingAttempts <= 0)
                {
                    // Lock User Account
                    await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(LockoutDurationMinutes));
                    await _auditLogService.LogAsync(user.Id, "Account locked due to multiple incorrect 2FA attempts");

                    // Clear OTP session
                    HttpContext.Session.Remove("2FA_OTP");
                    HttpContext.Session.Remove("2FA_Email");
                    HttpContext.Session.Remove("2FA_Attempts");

                    ModelState.AddModelError(string.Empty, "Too many incorrect attempts. Your account has been locked for 5 minutes.");
                    return RedirectToPage("/Account/Login");
                }

                // Save remaining attempts
                HttpContext.Session.SetInt32("2FA_Attempts", RemainingAttempts);
                ModelState.AddModelError(string.Empty, $"Invalid OTP. {RemainingAttempts} attempts remaining.");
            }

            return Page();
        }
    }
}

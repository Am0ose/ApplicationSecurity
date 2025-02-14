using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using ApplicationSecurity.Services;
using ApplicationSecurity.Models;

namespace ApplicationSecurity.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly EmailSenderService _emailSender;

        public ForgotPasswordModel(UserManager<User> userManager, EmailSenderService emailSender)
        {
            _userManager = userManager;
            _emailSender = emailSender;
        }

        [BindProperty]
        public ForgotPasswordInputModel Input { get; set; }

        public bool EmailSent { get; set; } = false;

        public class ForgotPasswordInputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }
        }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "If this email exists, a reset link has been sent.");
                return Page();
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetUrl = Url.Page("/Account/ResetPassword", null, new { email = Input.Email, token }, Request.Scheme);

            await _emailSender.SendEmailAsync(Input.Email, "Password Reset",
                $"Click <a href='{resetUrl}'>here</a> to reset your password.");

            EmailSent = true; //  Show success message

            return Page();
        }
    }
}

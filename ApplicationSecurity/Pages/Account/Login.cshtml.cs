using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using ApplicationSecurity.Services;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using ApplicationSecurity.Models;

namespace ApplicationSecurity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly AuditLogService _auditLogService;
        private readonly EmailSenderService _emailSender;
        private readonly ReCaptchaService _reCaptchaService;

        public LoginModel(SignInManager<User> signInManager,
                          UserManager<User> userManager,
                          ILogger<LoginModel> logger,
                          AuditLogService auditLogService,
                          EmailSenderService emailSender,
                          ReCaptchaService reCaptchaService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
            _auditLogService = auditLogService;
            _emailSender = emailSender;
            _reCaptchaService = reCaptchaService;
        }

        [BindProperty]
        public LoginInputModel Input { get; set; }

        [BindProperty]
        public string ReCaptchaToken { get; set; }

        public class LoginInputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }
        }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            _logger.LogInformation("Received reCAPTCHA token: {Token}", ReCaptchaToken);

            // Validate reCAPTCHA
            var isHuman = await _reCaptchaService.ValidateReCaptchaAsync(ReCaptchaToken);
            _logger.LogInformation("reCAPTCHA Validation Result: {IsHuman}", isHuman);
            if (!isHuman)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);

            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return Page();
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                ModelState.AddModelError(string.Empty, "Your account has been locked due to multiple failed login attempts. Try again later.");
                return Page();
            }

            var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, false, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                if (await _userManager.GetTwoFactorEnabledAsync(user))
                {
                    var otp = GenerateOTP();
                    HttpContext.Session.SetString("2FA_OTP", otp);
                    HttpContext.Session.SetString("2FA_Email", Input.Email);

                    await _emailSender.SendEmailAsync(Input.Email, "Your 2FA Code", $"Your verification code is: <b>{otp}</b>. It is valid for 5 minutes.");

                    return RedirectToPage("/Account/Verify2FA");
                }

                _logger.LogInformation("User logged in: {Email}", Input.Email);
                await _auditLogService.LogAsync(user.Id, "Successful login");

                // Store session expiry time (to track idle timeout)
                string expiryTime = DateTime.UtcNow.AddMinutes(20).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                HttpContext.Session.SetString("SessionExpiry", expiryTime);
                _logger.LogInformation("Session expiry set to: {ExpiryTime}", expiryTime);

                return RedirectToPage("/Index");
            }


            if (result.IsLockedOut)
            {
                await _auditLogService.LogAsync(user.Id, "Account locked due to failed login attempts");
                ModelState.AddModelError(string.Empty, "Your account is locked due to too many failed attempts.");
                return Page();
            }

            await _auditLogService.LogAsync(user.Id, "Failed login attempt");
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return Page();
        }

        private string GenerateOTP()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[4];
                rng.GetBytes(bytes);
                int code = BitConverter.ToInt32(bytes, 0) % 1000000; // 6-digit OTP
                return Math.Abs(code).ToString("D6");
            }
        }
    }
}

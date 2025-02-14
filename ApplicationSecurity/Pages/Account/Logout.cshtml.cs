using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using ApplicationSecurity.Services;
using ApplicationSecurity.Models;

namespace ApplicationSecurity.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        private readonly AuditLogService _auditLogService;
        private readonly UserManager<User> _userManager;

        public LogoutModel(SignInManager<User> signInManager,
                           ILogger<LogoutModel> logger,
                           AuditLogService auditLogService,
                           UserManager<User> userManager)
        {
            _signInManager = signInManager;
            _logger = logger;
            _auditLogService = auditLogService;
            _userManager = userManager;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                await _auditLogService.LogAsync(user.Id, "User logged out");
            }

            // Clear session before signing out
            HttpContext.Session.Clear();
            Response.Cookies.Delete(".AspNetCore.Identity.Application"); // Remove authentication cookie

            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToPage("/Account/Login");
        }

    }
}

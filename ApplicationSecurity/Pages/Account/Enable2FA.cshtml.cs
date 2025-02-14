using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using ApplicationSecurity.Models;

namespace ApplicationSecurity.Pages.Account
{
    public class Enable2FAModel : PageModel
    {
        private readonly UserManager<User> _userManager;

        public Enable2FAModel(UserManager<User> userManager)
        {
            _userManager = userManager;
        }

        [BindProperty]
        public bool Is2FAEnabled { get; set; }

        public async Task OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                Is2FAEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

            await _userManager.SetTwoFactorEnabledAsync(user, Is2FAEnabled);
            return RedirectToPage("/Index");
        }
    }
}

using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ApplicationSecurity.Data;
using Microsoft.EntityFrameworkCore;
using ApplicationSecurity.Models;

namespace ApplicationSecurity.Pages.Account
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ApplicationDbContext _context;

        private const int MinPasswordAgeDays = 1; // Users must wait at least 1 day before changing again
        private const int MaxPasswordAgeDays = 90; // Users must change their password after 90 days

        public ChangePasswordModel(UserManager<User> userManager,
                                   SignInManager<User> signInManager,
                                   ApplicationDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
        }

        [BindProperty]
        public ChangePasswordInputModel Input { get; set; }

        public bool PasswordChanged { get; set; } = false;
        public bool ForcePasswordChange { get; set; } = false;

        public class ChangePasswordInputModel
        {
            [Required]
            [DataType(DataType.Password)]
            public string CurrentPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters long.")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$",
                ErrorMessage = "Password must contain an uppercase letter, lowercase letter, number, and special character.")]
            public string NewPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; }
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Account/Login");
            }

            var lastPasswordChange = await _context.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.CreatedAt)
                .Select(p => p.CreatedAt)
                .FirstOrDefaultAsync();

            if (lastPasswordChange != default)
            {
                var daysSinceLastChange = (DateTime.UtcNow - lastPasswordChange).TotalDays;

                if (daysSinceLastChange >= MaxPasswordAgeDays)
                {
                    ForcePasswordChange = true;
                }
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found.");
                return Page();
            }

            var lastPasswordChange = await _context.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.CreatedAt)
                .Select(p => p.CreatedAt)
                .FirstOrDefaultAsync();

            if (lastPasswordChange != default)
            {
                var daysSinceLastChange = (DateTime.UtcNow - lastPasswordChange).TotalDays;

                if (daysSinceLastChange < MinPasswordAgeDays)
                {
                    ModelState.AddModelError(string.Empty, $"You must wait at least {MinPasswordAgeDays} day(s) before changing your password again.");
                    return Page();
                }
            }

            var result = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);

            if (result.Succeeded)
            {
                var hashedNewPassword = _userManager.PasswordHasher.HashPassword(user, Input.NewPassword);
                _context.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    HashedPassword = hashedNewPassword,
                    CreatedAt = DateTime.UtcNow
                });

                await _context.SaveChangesAsync();
                await _signInManager.RefreshSignInAsync(user);

                PasswordChanged = true;
                return Page();
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
    }
}

using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace ApplicationSecurity.Pages.Error
{
    public class ForbiddenModel : PageModel
    {
        private readonly ILogger<ForbiddenModel> _logger;

        public string ErrorMessage { get; private set; }

        public ForbiddenModel(ILogger<ForbiddenModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            ErrorMessage = "You do not have permission to access this page.";
            _logger.LogWarning("403 - Forbidden access attempt.");
        }
    }
}

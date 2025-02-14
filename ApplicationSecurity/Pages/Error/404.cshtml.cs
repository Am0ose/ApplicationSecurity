using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace ApplicationSecurity.Pages.Error
{
    public class NotFoundModel : PageModel
    {
        private readonly ILogger<NotFoundModel> _logger;

        public string ErrorMessage { get; private set; }

        public NotFoundModel(ILogger<NotFoundModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            ErrorMessage = "The page you are looking for does not exist.";
            _logger.LogWarning("404 - Page Not Found accessed.");
        }
    }
}

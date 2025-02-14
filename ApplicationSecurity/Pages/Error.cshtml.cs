using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace ApplicationSecurity.Pages
{
    public class ErrorModel : PageModel
    {
        private readonly ILogger<ErrorModel> _logger;

        public int? StatusCode { get; set; }
        public string ErrorMessage { get; set; }

        public ErrorModel(ILogger<ErrorModel> logger)
        {
            _logger = logger;
        }

        public void OnGet(int? code)
        {
            StatusCode = code ?? 500; // Default to 500 if no code is provided
            ErrorMessage = StatusCode switch
            {
                404 => "Page not found.",
                403 => "Access is denied.",
                500 => "An unexpected error occurred. Please try again later.",
                _ => "An error occurred."
            };

            _logger.LogError("Error {StatusCode} occurred", StatusCode);
        }
    }
}

using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace ApplicationSecurity.Pages.Error
{
    public class ServerErrorModel : PageModel
    {
        private readonly ILogger<ServerErrorModel> _logger;

        public string ErrorMessage { get; private set; }

        public ServerErrorModel(ILogger<ServerErrorModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            ErrorMessage = "Something went wrong on our end. Please try again later.";
            _logger.LogError("500 - Internal Server Error occurred.");
        }
    }
}

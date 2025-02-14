using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ApplicationSecurity.Pages
{
    public class TestModel : PageModel
    {
        public void OnGet()
        {
            throw new Exception("Test error!");
        }
    }
}

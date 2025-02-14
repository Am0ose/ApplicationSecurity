using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Text.Json.Serialization;

namespace ApplicationSecurity.Services
{
    public class ReCaptchaService
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly ILogger<ReCaptchaService> _logger;

        public ReCaptchaService(IConfiguration configuration, HttpClient httpClient, ILogger<ReCaptchaService> logger)
        {
            _configuration = configuration;
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<bool> ValidateReCaptchaAsync(string token)
        {
            var secretKey = _configuration["GoogleReCaptcha:SecretKey"];
            var apiUrl = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}";

            var response = await _httpClient.GetAsync(apiUrl);
            var json = await response.Content.ReadAsStringAsync();
            var reCaptchaResponse = JsonSerializer.Deserialize<ReCaptchaResponse>(json);

            _logger.LogInformation("reCAPTCHA API Response: {Json}", json);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to reach Google reCAPTCHA API. Status Code: {StatusCode}", response.StatusCode);
                return false;
            }

            if (!reCaptchaResponse.Success)
            {
                _logger.LogWarning("reCAPTCHA validation failed. Errors: {Errors}", string.Join(", ", reCaptchaResponse.ErrorCodes ?? new string[0]));
                return false;
            }

            // Debugging: Log received values
            _logger.LogInformation("reCAPTCHA Success: {Success}", reCaptchaResponse.Success);
            _logger.LogInformation("reCAPTCHA Score: {Score}", reCaptchaResponse.Score);
            _logger.LogInformation("reCAPTCHA Action: {Action}", reCaptchaResponse.Action);

            // Ensure the action matches 'login'
            if (!string.Equals(reCaptchaResponse.Action, "login", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("reCAPTCHA action mismatch. Expected 'login' but received '{Action}'", reCaptchaResponse.Action);
                return false;
            }

            // Accept anything above 0.3
            if (reCaptchaResponse.Score < 0.3)
            {
                _logger.LogWarning("reCAPTCHA score too low ({Score}). Possible bot detected.", reCaptchaResponse.Score);
                return false;
            }

            // Return true since all validations passed
            return true;
        }




    }

    public class ReCaptchaResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; } 

        [JsonPropertyName("challenge_ts")]
        public string ChallengeTs { get; set; }  

        [JsonPropertyName("hostname")]
        public string Hostname { get; set; }

        [JsonPropertyName("score")]
        public float Score { get; set; }

        [JsonPropertyName("action")]
        public string Action { get; set; }

        [JsonPropertyName("error-codes")]
        public string[] ErrorCodes { get; set; }
    }
}

using Microsoft.Extensions.Configuration;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace ApplicationSecurity.Services
{
    public class TwoFactorAuthService
    {
        private readonly IConfiguration _configuration;
        private readonly Random _random = new();

        public TwoFactorAuthService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<string> GenerateAndSendCodeAsync(string userEmail)
        {
            var smtpSettings = _configuration.GetSection("SmtpSettings");

            using var client = new SmtpClient
            {
                Host = smtpSettings["Server"],
                Port = int.Parse(smtpSettings["Port"]),
                EnableSsl = true,
                Credentials = new NetworkCredential(smtpSettings["SenderEmail"], smtpSettings["SenderPassword"])
            };

            string code = _random.Next(100000, 999999).ToString(); // 6-digit code

            var mailMessage = new MailMessage
            {
                From = new MailAddress(smtpSettings["SenderEmail"]),
                Subject = "Your 2FA Code",
                Body = $"Your authentication code is: <b>{code}</b>",
                IsBodyHtml = true
            };

            mailMessage.To.Add(userEmail);
            await client.SendMailAsync(mailMessage);

            return code; // Return code for validation
        }
    }
}

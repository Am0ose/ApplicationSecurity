using Microsoft.Extensions.Configuration;
using System;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ApplicationSecurity.Services
{
    public class EmailSenderService
    {
        private readonly IConfiguration _configuration;

        public EmailSenderService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            var smtpSettings = _configuration.GetSection("SmtpSettings");

            using var client = new SmtpClient
            {
                Host = smtpSettings["Server"],
                Port = int.Parse(smtpSettings["Port"]),
                EnableSsl = true, // Ensures STARTTLS is used
                Credentials = new NetworkCredential(smtpSettings["SenderEmail"], smtpSettings["SenderPassword"])
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(smtpSettings["SenderEmail"]),
                Subject = subject,
                Body = message,
                IsBodyHtml = true
            };

            mailMessage.To.Add(toEmail);
            await client.SendMailAsync(mailMessage);
        }

        //  Function to Generate and Send OTP for 2FA
        public async Task<string> SendOTPAsync(string toEmail)
        {
            string otp = GenerateOTP();

            string subject = "Your 2FA Verification Code";
            string message = $"Your One-Time Password (OTP) for login is: <b>{otp}</b>. It is valid for 5 minutes.";

            await SendEmailAsync(toEmail, subject, message);
            return otp; // Return OTP for verification
        }

        // Secure OTP Generator
        private string GenerateOTP()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[4];
                rng.GetBytes(bytes);
                int otpCode = BitConverter.ToInt32(bytes, 0) % 1000000; // 6-digit OTP
                return Math.Abs(otpCode).ToString("D6");
            }
        }
    }
}

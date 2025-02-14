using ApplicationSecurity.Data;
using Microsoft.AspNetCore.Identity;
using System;
using System.Threading.Tasks;

namespace ApplicationSecurity.Services
{
    public class AuditLogService
    {
        private readonly ApplicationDbContext _context;

        public AuditLogService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task LogAsync(string userId, string action)
        {
            if (string.IsNullOrEmpty(userId)) return;

            var log = new AuditLog
            {
                UserId = userId,
                Action = action,
                Timestamp = DateTime.UtcNow
            };

            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();
        }
    }
}

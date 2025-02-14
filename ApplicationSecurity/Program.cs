using ApplicationSecurity.Data;
using ApplicationSecurity.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ApplicationSecurity.Models;

var builder = WebApplication.CreateBuilder(args);

// Configure Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseMySql(builder.Configuration.GetConnectionString("DefaultConnection"),
        new MySqlServerVersion(new Version(8, 0, 32))));

// Configure Identity with Security Policies
builder.Services.AddIdentity<User, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;

    // Account Lockout Policy
    options.Lockout.MaxFailedAccessAttempts = 3;  // Lock account after 3 failed attempts
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Lockout for 5 minutes
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Configure Authentication Cookies
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60); //Match idletimeout to auto logout
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Error/403"; // Redirect unauthorized access to Error page
    options.SlidingExpiration = true;
});

// Add Session Services
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(10); // OTP and Session expiry (change to 1minute for demo)
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.AddRazorPages();
builder.Services.AddScoped<AuditLogService>();
builder.Services.AddScoped<EmailSenderService>();
builder.Services.AddScoped<TwoFactorAuthService>();
builder.Services.AddHttpClient<ReCaptchaService>();
builder.Services.Configure<ReCaptchaService>(builder.Configuration.GetSection("GoogleReCaptcha"));

var app = builder.Build();

// Global Exception Handling
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error"); // Handle unhandled exceptions
    app.UseStatusCodePagesWithReExecute("/Error/{0}"); // Handle status codes like 404, 403, etc.
}
else
{
    app.UseDeveloperExceptionPage(); // For debugging in development mode
}

// Middleware Pipeline
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

//Enable Session Middleware (Required for 2FA)
app.UseSession();

app.MapRazorPages();

// Explicit 404 Handling - Ensures users see a friendly 404 page
app.Use(async (context, next) =>
{
    await next();

    if (context.Response.StatusCode == 404)
    {
        context.Request.Path = "/Error/404";
        await next();
    }
});

app.Run();

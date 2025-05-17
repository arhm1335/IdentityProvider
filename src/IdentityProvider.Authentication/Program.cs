using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

const AuthenticationHandlerType authenticationHandlerDefault = AuthenticationHandlerType.Cookie;

builder.Services.AddDataProtection();

builder.Services.AddKeyedScoped<IAuthenticationHandler, CookieAuthenticationHandler>(AuthenticationHandlerType.Cookie);
builder.Services.AddKeyedScoped<IAuthenticationHandler, HeaderAuthenticationHandler>(AuthenticationHandlerType.Header);

var app = builder.Build();

app.Use((context, next) =>
{
    var serviceProvider =
        context.RequestServices.GetService<IServiceProvider>()
        ?? throw new ArgumentNullException(nameof(IServiceProvider));

    var authenticationHandler =
        serviceProvider.GetKeyedService<IAuthenticationHandler>(authenticationHandlerDefault)
        ?? throw new ArgumentNullException(nameof(authenticationHandlerDefault));

    authenticationHandler.AuthenticateAsync(context);

    return next(context);
});

app.MapGet("/",
    (HttpContext httpContext) => httpContext.User.Identity!.Name is { } username
        ? Results.Ok((object?)username)
        : Results.NotFound());

app.MapPost("/login/{username}", (
    string username, IDataProtectionProvider dataProtectionProvider, HttpContext httpContext) =>
{                                                                         
    var protector = dataProtectionProvider.CreateProtector(CookieAuthenticationHandler.PurposeProtector);
    var protectedUsername = protector.Protect(username);

    httpContext.Response.Cookies.Append(CookieAuthenticationHandler.CookieName, protectedUsername,
        options: new CookieOptions()
        {
            Expires = DateTime.UtcNow.AddHours(5)
        });
});

app.Run();


internal interface IAuthenticationHandler
{
    Task AuthenticateAsync(HttpContext context);
}

enum AuthenticationHandlerType
{
    Cookie = 0,
    Header = 1
}

internal class CookieAuthenticationHandler(IDataProtectionProvider dataProtectionProvider) : IAuthenticationHandler
{
    public const string PurposeProtector = "Authentication";
    public const string CookieName = "username";

    public async Task AuthenticateAsync(HttpContext context)
    {
        if (!context.Request.Cookies.TryGetValue(CookieName, out var username))
            throw new Exception("Invalid username");

        var protector = dataProtectionProvider.CreateProtector(PurposeProtector);
        var usernameDecrypted = protector.Unprotect(username);

        var claims = new List<Claim> { new(ClaimTypes.Name, usernameDecrypted) };
        var claimsIdentity = new ClaimsIdentity(claims);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        context.User = claimsPrincipal;

        throw new Exception("Invalid username");
    }
}

internal class HeaderAuthenticationHandler : IAuthenticationHandler
{
    public const string HeaderName = "username";

    public async Task AuthenticateAsync(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue(HeaderName, out var username))
            throw new Exception("Invalid username");

        var claims = new List<Claim> { new(ClaimTypes.Name, username) };
        var claimsIdentity = new ClaimsIdentity(claims);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        context.User = claimsPrincipal;

        throw new Exception("Invalid username");
    }
}
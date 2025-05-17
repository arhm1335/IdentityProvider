using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();
builder.Services.AddDataProtection(options => { options.ApplicationDiscriminator = "IdentityProvider.Basic"; });
builder.Services.AddTransient<UserAuthenticationService>();

var app = builder.Build();

app.MapGet("/", (UserAuthenticationService userAuthenticationService) =>
{
    var username = userAuthenticationService.GetUsername();
    return username != null ? Results.Ok(username) : Results.NotFound();
});

app.MapPost("/login/{username}", (
    string username,
    UserAuthenticationService userAuthenticationService) =>
{
    userAuthenticationService.SignIn(username);
});

app.Run();

internal class UserAuthenticationService(
    IHttpContextAccessor httpContextAccessor,
    IDataProtectionProvider dataProtectionProvider)
{
    private const string CookieUserName = "username";
    private const string PurposeProtector = "IdentityProvider.Basic_Protect-Username";
    private readonly HttpContext _httpContext = httpContextAccessor.HttpContext!;

    public void SignIn(string username)
    {
        var protector = dataProtectionProvider.CreateProtector(PurposeProtector);
        var protectedUsername = protector.Protect(username);

        _httpContext.Response.Cookies.Append(CookieUserName, protectedUsername,
            options: new CookieOptions()
            {
                Expires = DateTime.UtcNow.AddHours(5)
            });
    }

    public string? GetUsername()
    {
        if (!_httpContext.Request.Cookies.TryGetValue(CookieUserName, out var username))
            return null;

        var protector = dataProtectionProvider.CreateProtector("IdentityProvider.Basic_Protect-Username");
        var protectedUsername = protector.Unprotect(username);

        return protectedUsername;
    }
}
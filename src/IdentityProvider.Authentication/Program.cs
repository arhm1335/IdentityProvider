using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddCookie("idp", options =>
    {
        options.Cookie.Name = "idp";
    })
    .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationOptions.DefaultApiKeyAuthenticationScheme, options =>
        {
            options.HeaderName = "un";
            options.ApiKeyValue = "arhm";
        });

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/", (HttpContext httpContext) =>
{
    var username = httpContext.User.Identity?.Name;

    return Results.Ok($"username: {username}");
});

app.MapPost("/login/{username}", async (
    string username, HttpContext httpContext) =>
{
    var claims = new List<Claim> { new(ClaimTypes.Name, username) };
    var claimsIdentity = new ClaimsIdentity(claims, "idp");
    var userPrincipal = new ClaimsPrincipal(claimsIdentity);

    await httpContext.SignInAsync("idp",userPrincipal);

    return Results.Ok("success login");
});

app.Run();

public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string DefaultApiKeyAuthenticationScheme = "apikey";
    public string HeaderName { get; set; } = "api-key";
    public string ApiKeyValue { get; set; }
}

public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Request.Headers.TryGetValue(Options.HeaderName, out var username))
        {
            var apiKey = username;
            if (apiKey != Options.ApiKeyValue)
                return AuthenticateResult.Fail("Invalid API Key");

            var claims = new List<Claim> { new(ClaimTypes.Name, username) };
            var claimsIdentity =
                new ClaimsIdentity(claims, ApiKeyAuthenticationOptions.DefaultApiKeyAuthenticationScheme);
            var userPrincipal = new ClaimsPrincipal(claimsIdentity);

            var ticket = new AuthenticationTicket(userPrincipal,
                ApiKeyAuthenticationOptions.DefaultApiKeyAuthenticationScheme);
            return AuthenticateResult.Success(ticket);
        }

        return AuthenticateResult.Fail("username not found in header");
    }

    public ApiKeyAuthenticationHandler(IOptionsMonitor<ApiKeyAuthenticationOptions> options, ILoggerFactory logger,
        UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    public ApiKeyAuthenticationHandler(IOptionsMonitor<ApiKeyAuthenticationOptions> options, ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {
    }
}
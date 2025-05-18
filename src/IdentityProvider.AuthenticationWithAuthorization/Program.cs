using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("idp")
    .AddCookie("idp", options =>
    {
        options.LoginPath = "/login/a";
        options.Cookie.Name = "idp";
    })
    .AddScheme<HeaderOptions, HeaderHandler>("header", options =>
    {
        options.ApiKey = "123";
        options.HeaderName = "aut";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("idp-policy", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddAuthenticationSchemes("idp");
        policy.AddRequirements(new AssertionRequirement(a => a.User.Identities
            .Any(i => i.AuthenticationType == "idp")
        ));
    });
    options.AddPolicy("header-policy", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddAuthenticationSchemes("header");
        policy.AddRequirements(new AssertionRequirement(a => a.User.Identities
            .Any(i => i.AuthenticationType == "header")
        ));
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext httpContext) =>
{
    var username = httpContext.User.Identity?.Name;

    return Results.Ok($"username: {username}");
}).RequireAuthorization(["idp-policy", "header-policy"]);

app.MapGet("/idp", (HttpContext httpContext) =>
{
    var username = httpContext.User.Identity?.Name;

    return Results.Ok($"username: {username}");
}).RequireAuthorization(["idp-policy"]);

app.MapGet("/header", (HttpContext httpContext) =>
{
    var username = httpContext.User.Identity?.Name;

    return Results.Ok($"username: {username}");
}).RequireAuthorization(["header-policy"]);


app.MapPost("/login/{username}", async (
    string username, HttpContext httpContext) =>
{
    var claims = new List<Claim> { new(ClaimTypes.Name, username) };
    var claimsIdentity = new ClaimsIdentity(claims, "idp");
    var userPrincipal = new ClaimsPrincipal(claimsIdentity);

    await httpContext.SignInAsync("idp", userPrincipal);

    return Results.Ok("success login");
});

app.Run();


public class HeaderOptions : AuthenticationSchemeOptions
{
    public string HeaderName { get; set; } = "X-Idp-Username";
    public string ApiKey { get; set; }
}

public class HeaderHandler : AuthenticationHandler<HeaderOptions>
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Context.Request.Headers.TryGetValue(Options.HeaderName, out var apiKey))
            if (apiKey == Options.ApiKey)
            {
                var claims = new List<Claim> { new(ClaimTypes.Name, "ali") };
                var claimsIdentity =
                    new ClaimsIdentity(claims, "header");
                var userPrincipal = new ClaimsPrincipal(claimsIdentity);

                var ticket = new AuthenticationTicket(userPrincipal,
                    "header");
                return AuthenticateResult.Success(ticket);
            }

        return AuthenticateResult.Fail("invalid api key");
    }

    public HeaderHandler(IOptionsMonitor<HeaderOptions> options, ILoggerFactory logger, UrlEncoder encoder,
        ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    public HeaderHandler(IOptionsMonitor<HeaderOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(
        options, logger, encoder)
    {
    }
}
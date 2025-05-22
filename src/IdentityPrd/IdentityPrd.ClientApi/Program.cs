using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

var authServerUrl = builder.Configuration["OAuth:ServerUrl"] !
                    ?? throw new ArgumentNullException($"Server Url");

builder.Services.AddAuthentication(AuthenticationScheme.Cookie)
    .AddCookie(AuthenticationScheme.Cookie, options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.Cookie.Name = "IdentityPrd";
    })
    .AddOAuth(AuthenticationScheme.GitHub, options =>
    {
        options.SignInScheme = AuthenticationScheme.Cookie;

        options.ClientId = builder.Configuration["OAuth:GitHub:ClientId"] ??
                           throw new ArgumentNullException($"ClientId");
        options.ClientSecret = builder.Configuration["OAuth:GitHub:ClientSecret"] ??
                               throw new ArgumentNullException($"ClientSecret");

        options.UsePkce = true;

        options.AuthorizationEndpoint = $"{authServerUrl}/login/oauth/authorize";
        options.TokenEndpoint = $"{authServerUrl}/login/oauth/access_token";
        options.UserInformationEndpoint = $"{authServerUrl}/user";
        options.CallbackPath = "/oauth/signin-oidc";

        options.SaveTokens = true;

        options.Scope.Add("repo:status");

        options.Events.OnCreatingTicket = async context =>
        {
            var accessToken = context.AccessToken;

            var httpRequest = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await context.Backchannel.SendAsync(httpRequest, context.HttpContext.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                context.Fail($"Failed to retrieve user information: {response.StatusCode}");
                return;
            }

            using var user = await System.Text.Json.JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            foreach (var property in user.RootElement.EnumerateObject())
                context.Identity?.AddClaim(new Claim(property.Name, property.Value.ToString()));
            context.Identity?.AddClaim(new Claim("access_token", accessToken));
        };
    });

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/login", ([FromQuery(Name = "returnUrl")] string? returnUrl) =>
Results.Challenge(new OAuthChallengeProperties()
    { RedirectUri = returnUrl ?? "https://localhost:7051/get-data" }, [AuthenticationScheme.GitHub]));

app.MapGet("/get-data", async (HttpContext context) =>
{
    var claims = context.User.Claims.Select(c=>new {c.Type, c.Value});
    return Results.Ok(new
    {
        Claims = claims,
        IsAuthenticated = context.User.Identity?.IsAuthenticated,
    });
});

app.Run();

public static class AuthenticationScheme
{
    public const string Default = Cookie;
    public const string GitHub = "github";
    public const string Cookie = "cookie";
}
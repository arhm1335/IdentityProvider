using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthenticationScheme.Cookie)
    .AddCookie(AuthenticationScheme.Cookie, options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.Cookie.Name = "IdentityOAut";
    })
    .AddOAuth(AuthenticationScheme.GitHub, options =>
    {
        options.SignInScheme = AuthenticationScheme.Cookie;

        options.ClientId = builder.Configuration["OAut:GitHub:ClientId"] ??
                           throw new ArgumentNullException($"ClientId");
        options.ClientSecret = builder.Configuration["OAut:GitHub:ClientSecret"] ??
                               throw new ArgumentNullException($"ClientSecret");
        
        options.UsePkce = true;

        options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        options.TokenEndpoint = "https://github.com/login/oauth/access_token";
        options.UserInformationEndpoint = "https://api.github.com/user";
        options.CallbackPath = "/dashboard2";
        
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

app.MapGet("/login-github", ([FromQuery(Name = "returnUrl")] string? returnUrl) =>
Results.Challenge(new OAuthChallengeProperties()
    { RedirectUri = returnUrl ?? "/dashboard"}, [AuthenticationScheme.GitHub]));

app.MapGet("/dashboard", (HttpContext context) =>
{ 
   
});

app.MapGet("/user-data", (HttpContext context) =>
{
var claims = context.User.Claims.Select(c=>new {c.Type, c.Value});
    return Results.Ok(new
    {
        IsAuthenticated = context.User.Identity.IsAuthenticated,
        Claims = claims
    });
});

app.Run();

public static class AuthenticationScheme
{
    public const string Default = Cookie;
    public const string GitHub = "github";
    public const string Cookie = "cookie";
}
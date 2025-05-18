using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("idp")
    .AddCookie("idp", options =>
    {
        options.LoginPath = "/login/a";
        options.Cookie.Name = "idp";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("idp", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(ClaimTypes.Name);
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext httpContext) =>
{
    var username = httpContext.User.Identity?.Name;

    return Results.Ok($"username: {username}");
}).RequireAuthorization("idp");

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
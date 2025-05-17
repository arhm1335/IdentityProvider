using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddCookie("idp",options =>
    {
        
    });

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/", (HttpContext httpContext) =>
{
    var username = httpContext.User.Identity?.Name;

    return Results.Ok($"username: {username}");
});

app.MapPost("/login/{username}", (
    string username, HttpContext httpContext) =>
{
    var claims = new List<Claim> { new(ClaimTypes.Name, username) };
    var claimsIdentity = new ClaimsIdentity(claims, "idp");
    var userPrincipal = new ClaimsPrincipal(claimsIdentity);

    httpContext.SignInAsync( userPrincipal);

    return Results.Ok("success login");
});

app.Run();
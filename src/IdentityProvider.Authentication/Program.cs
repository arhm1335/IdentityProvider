using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("idp")
    .AddCookie("idp", options =>
    {
        options.Cookie.Name = "idp";
    });

var app = builder.Build();

app.UseAuthentication();

app.Use((context, next) =>
{
    if(context.GetEndpoint().Metadata.Any(a=>a is IAllowAnonymous))
        return next(context);
    
    if (context.User.Identity?.IsAuthenticated != true)
         context.Response.StatusCode = 401;

    if (!context.User.HasClaim(ClaimTypes.Name, "arhm"))
        context.Response.StatusCode = 401;
    
    return next(context);
});

app.MapGet("/", (HttpContext httpContext) =>
{
    if (httpContext.User.Identity?.IsAuthenticated != true)
        return Results.Unauthorized();

    if (!httpContext.User.HasClaim(ClaimTypes.Name, "arhm"))
        return Results.Unauthorized();
    
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
}).AllowAnonymous();

app.Run();

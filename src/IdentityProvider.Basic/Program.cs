using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection(options => { options.ApplicationDiscriminator = "IdentityProvider.Basic"; });

var app = builder.Build();

app.MapGet("/", (HttpContext context, IDataProtectionProvider dataProtectionProvider) =>
{
    if (!context.Request.Cookies.TryGetValue("username", out var username))
        return Results.NotFound();

    var protector = dataProtectionProvider.CreateProtector("IdentityProvider.Basic_Protect-Username");
    var protectedUsername = protector.Unprotect(username);

    return Results.Ok(protectedUsername);
});

app.MapPost("/login/{username}",
    (string username, HttpContext context, IDataProtectionProvider dataProtectionProvider) =>
    {
        var protector = dataProtectionProvider.CreateProtector("IdentityProvider.Basic_Protect-Username");
        var protectedUsername = protector.Protect(username);

        context.Response.Cookies.Append("username", protectedUsername, new CookieOptions()
        {
            Expires = DateTime.UtcNow.AddHours(5)
        });
    });

app.Run();
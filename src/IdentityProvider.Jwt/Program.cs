using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Ensure options.TokenValidationParameters is not null
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Example configuration (adjust as needed)
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            // Ensure IssuerSigningKey is set
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key is not configured"))
            ),
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"]
        };

        options.Events = new JwtBearerEvents()
        {
            OnMessageReceived = context =>
            {
                if (context.Request.Headers.TryGetValue("token", out var token))
                {
                    context.Token = token;
                   // context.Success();
                    return Task.CompletedTask;
                }
                context.Fail("invalid token");
                return Task.CompletedTask;
            },
        };
    });

var app = builder.Build();

app.UseAuthentication();

app.MapPost("/jwt-set", async (HttpContext context) =>
{
    var claims = new[]
    {
        new Claim("name", "example_user"),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: builder.Configuration["Jwt:Issuer"],
        audience: builder.Configuration["Jwt:Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(30),
        signingCredentials: creds);

    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

    await context.Response.WriteAsync(tokenString);
});

app.MapGet("/jwt-get/{token}", ([FromRoute(Name = "token")]string tokenString) =>
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.ReadJwtToken(tokenString);
    return token;
});

app.MapGet("/auth",async (HttpContext context) =>
{
    var data = context.User.FindFirst("name")?.Value;
    return data?? "null";
});


app.Run();
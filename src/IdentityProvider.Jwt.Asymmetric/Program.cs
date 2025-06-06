using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient("token_provider",
    options => { options.BaseAddress = new Uri(" https://localhost:7216"); });
builder.Services.AddSingleton<TokenWrapper>();
builder.Services.AddHostedService<TokenCleanUpBackgroundService>();

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
            IssuerSigningKey = new RsaSecurityKey(KeyAuth.ReadAuthPublicKey()),
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"]
        };

        options.Events = new JwtBearerEvents()
        {
            OnMessageReceived = async context =>
            {
                if (context.Request.Headers.ContainsKey("access-token"))
                    return;
                
                if (!context.Request.Headers.TryGetValue("token", out var token))
                    context.Fail("invalid token");

                var httpFactory = context.HttpContext.RequestServices.GetRequiredService<IHttpClientFactory>();
                var httpClient = httpFactory.CreateClient("token_provider");
                httpClient.DefaultRequestHeaders.Add("access-token", [token]);

                try
                {
                    var validateResult = await httpClient.GetAsync("/token-validation");
                    validateResult.EnsureSuccessStatusCode();
                    
                    if (await validateResult.Content.ReadFromJsonAsync<bool>(CancellationToken.None) != true)
                        context.Fail("token expired!");
                }
                catch
                {
                    context.Fail("invalid request");
                }

                context.Token = token;
            },
        };
    });

var app = builder.Build();


app.MapPost("/jwt-set", async (HttpContext context, TokenWrapper tokenWrapper) =>
{
    var rsaKey = RSA.Create();

    //var privateKey = rsaKey.ExportRSAPrivateKey();
    //var publicKey = rsaKey.ExportRSAPublicKey();

    rsaKey.FromXmlString(KeyAuth.PrivateKey);
    var rsaKeySecurity = new RsaSecurityKey(rsaKey);
    string username = "example-user";

    var claims = new[]
    {
        new Claim("name", username),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

    var creds = new SigningCredentials(rsaKeySecurity, SecurityAlgorithms.RsaSha256);
    var expier = DateTime.UtcNow.Add(TokenWrapper.Expiry);
    var token = new JwtSecurityToken(
        issuer: builder.Configuration["Jwt:Issuer"],
        audience: builder.Configuration["Jwt:Audience"],
        claims: claims,
        expires: expier,
        signingCredentials: creds);

    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
    tokenWrapper.AddToken(username, tokenString, expier);
    await context.Response.WriteAsync(tokenString);
});

app.MapGet("/faire-user", (TokenWrapper tokenWrapper) =>
{
    tokenWrapper.RemoveToken("example-user");
    return Results.Ok("User fired");
});

app.MapGet("/token-validation", ([FromHeader(Name = "access-token")] string token, TokenWrapper tokenWrapper) =>
{
    var result = tokenWrapper.CheckValidToken(token);
    return Results.Ok(result);
});

//from another project (for example)
app.MapGet("/jwt-get", (HttpContext context) => context.User.FindFirst("name")?.Value ?? "null");

app.Run();

public class TokenWrapper
{
    public static readonly TimeSpan Expiry = TimeSpan.FromHours(2);
    private readonly HashSet<UserToken> _userTokens = [];

    public void AddToken(string username, string token, DateTime expires)
    {
        var tokenByte = Encoding.UTF8.GetBytes(token);
        var hasToken = SHA256.HashData(tokenByte);
        var tokenString = Convert.ToBase64String(hasToken);

        _userTokens.Add(new UserToken(username, tokenString, expires));
    }

    public void RemoveToken(string username)
    {
        _userTokens.RemoveWhere(u => u.Username == username);
    }

    public bool CheckValidToken(string token)
    {
        var tokenByte = Encoding.UTF8.GetBytes(token);
        var hasToken = SHA256.HashData(tokenByte);
        var tokenString = Convert.ToBase64String(hasToken);

        return _userTokens.Any(u => u.Token == tokenString);
    }

    public void CleanUp()
    {
        var now = DateTime.UtcNow;
        _userTokens.RemoveWhere(u => u.Expires < now);
    }
}

public record UserToken(string Username, string Token, DateTime Expires);

public static class KeyAuth
{
    private const string _privateKey =
        "<RSAKeyValue><Modulus>p03nX3cVjJGMt3W6POvIj1D2W8Mpj4mZNiZN66XnCfB61fhgbKQk6M09ZobJAaM/EYfJDaksDeFoXYmxW3nQDdMJthSxei8L0vM9VRZ255l3WwlLO5JViHxHVnbnmnHU4SCskw/aZSsHd4bEyPTBOjpq5MC+H5M6fqZ2MGCwAFKcp27de/X0J+/78OFPYyaPsDEbr24pgGAN977Y5h7uGwCwlj7Ov4vWoAdTt+igo0d91JgP4BSUpaiCAo72oq9oc/BG1v6al+maqWH0qcXNzlhq016I8ipTWV7ZF3FKdFAiV+REbvqMoD/2G6/o8LB5Y9S5tHcZWo8QToe9EP41rQ==</Modulus><Exponent>AQAB</Exponent><P>0yzvJl25Ku/nx0N8f3uxEHxqKFZC/3YZ5B9u+WFSZo0nk8SNXY2LLekBKDGKLYROB1tHM6L+lQQyS60jQ5J9eK7QUbQrOG+mlUGtbSXB4iqL4E/PO/tv446tTdnQ/saH0yqMZD4aDfKoglPRDmFxICwfOa/sFH+LYitHv33rIVs=</P><Q>ytENUNFDWWvavn8wzAdeb33UoRPZnvMhBs2IUsfeJVXlyiuF67MxhET4RbEaGZNMQdr4/cJJFY6t9W0P7UA8aBWq1ELpxAtx18eLdH1HkD3/lXIKHZxyZRkGzES12UFtjvZfbLvHsdOtHyoBOigx7VPMQJwRCdYDPDdwatM965c=</Q><DP>nzyA0MNXf0ML2TvQQyj4KWBHhEcXmh5qA5SYT7/NLLs/nrNVjbfPvTy3vKEueogLdoyjshI0OhXB/0J9FtT9e+UF/LYI6TN3v5CYv3b7Lhm7A9fqgmZkxoitsciPSa5WeSraVjRl3SKfYjblqxxa+1GJ8ivvrr1GUy4jmgfPJ4U=</DP><DQ>veyUNpkwI33fgsJitL01ztwbkJehE7sDs3Ym8bYergHJRNALAdR1SzK297RIB6krIQRoZGFaxSgueQSfhIHBz4pyxYC/nglFm1ZOnlBvAoE8ZPs8w8vsSAXumrzBOeiOKvFGHPGfqEPb+7H/IjHfxynQvLQpNHfH4czcpfyZIJM=</DQ><InverseQ>riUE8YHeT6lOBo7ceJC4ZQRgdCe2dw+6hj3lyoJy2FEAbbF5NFiRFmu+jB/JsWc7+LSJeYCeAexbuG5pPfabGJeeGODlJN5/r1F4Yv3FPRWX8yqGqLlyrRRpfq74atydXZMpfCjgqM6L01kckQGid6+LLXk6yzepsMlD6mx6yCE=</InverseQ><D>PG2H71Q8xUvg7naoMM7c3t7YTKZ+AWkqnINTS5TdkRp504TllvfmmOtgjQKL4XqMEhHgTX3X+p96qaZNGAQ0YHnkHQ72V3Jcq/HNKkl14wrsMEZ4FOky2ZxBy/oghwksYbAChQ+Jy1ayWLqlowu8KwLkjwEK6q6rxwjq0WhqyYJ3qM44Iv9JIQ8ei2ugJrVNqGMA0ia0vURdlswiii7z7M+G/5vimL3KpSNd6xzH1wpVYgfMxL/0n5oSz5ouJYHCY15D5Hwl7rSi7SFIzPsFbAyOS6i2RL6WljtcxN0xPO++U1yDnzy46NCZhXeCMxaG7IfXri24u8LAYvLTR1R/ZQ==</D></RSAKeyValue>";

    private const string _publicKey =
        "<RSAKeyValue><Modulus>p03nX3cVjJGMt3W6POvIj1D2W8Mpj4mZNiZN66XnCfB61fhgbKQk6M09ZobJAaM/EYfJDaksDeFoXYmxW3nQDdMJthSxei8L0vM9VRZ255l3WwlLO5JViHxHVnbnmnHU4SCskw/aZSsHd4bEyPTBOjpq5MC+H5M6fqZ2MGCwAFKcp27de/X0J+/78OFPYyaPsDEbr24pgGAN977Y5h7uGwCwlj7Ov4vWoAdTt+igo0d91JgP4BSUpaiCAo72oq9oc/BG1v6al+maqWH0qcXNzlhq016I8ipTWV7ZF3FKdFAiV+REbvqMoD/2G6/o8LB5Y9S5tHcZWo8QToe9EP41rQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    public static string PrivateKey => _privateKey;

    public static RSACryptoServiceProvider ReadAuthPublicKey()
    {
        var rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(_publicKey);
        return rsa;
    }
}

public class TokenCleanUpBackgroundService(TokenWrapper tokenWrapper): BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            tokenWrapper.CleanUp();
            await Task.Delay(TokenWrapper.Expiry, stoppingToken);
        }
    }
}
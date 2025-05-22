using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthenticationScheme.Cookie)
    .AddCookie(AuthenticationScheme.Cookie, options =>
    {
        options.LoginPath = "/account/login";
        options.LogoutPath = "/account/logout";
    });

builder.Services.AddAuthorization();

builder.Services.AddDataProtection()
    .SetApplicationName("identity-idp.server");

var app = builder.Build();

app.UseHttpsRedirection();
app.UseHsts();

app.UseAuthentication();
app.UseAuthorization();

#region Server Endpoints

app.MapGet("/login/oauth/authorize", (
    IDataProtectionProvider protectionProvider,
    [FromQuery(Name = "response_type")] string responseType,
    [FromQuery(Name = "client_id")] string clientId,
    [FromQuery(Name = "state")] string state,
    [FromQuery(Name = "redirect_uri")] string redirectUri,
    [FromQuery(Name = "code_challenge")] string codeChallenge,
    [FromQuery(Name = "code_challenge_method")]
    string codeChallengeMethod
) =>
{
    //todo validate these information
    //todo validate client and grant
    //todo validate client scope
    //todo validate state

    var code = new AuthorizationCode()
    {
        ClientId = clientId,
        CodeChallenge = codeChallenge,
        CodeChallengeMethod = codeChallengeMethod,
        ReturnUrl = redirectUri,
        Expiry = DateTime.UtcNow.AddMinutes(10)
    };

    var protector = protectionProvider.CreateProtector("authorization_code");
    var protectedCode = protector.Protect(JsonSerializer.Serialize(code));

    //save to db => protectedCode

    return Results.Redirect(
        $"{redirectUri}?code={protectedCode}&state={state}&iis={HttpUtility.UrlEncode("https://localhost:7051")}");
}).RequireAuthorization();

app.MapPost("/login/oauth/access_token", async (
    HttpRequest request,
    IDataProtectionProvider protectionProvider,
    [FromForm(Name = "grant_type")] string grantType,
    [FromForm(Name = "code")] string code,
    [FromForm(Name = "redirect_uri")] string redirectUri,
    [FromForm(Name = "code_verifier")] string codeVerifier
) =>
{
    //validations
    //data load stored from the database 

    var protector = protectionProvider.CreateProtector("authorization_code");
    var unProtectedCode = JsonSerializer.Deserialize<AuthorizationCode>(protector.Unprotect(code));

    var decodeChallengeCode = Base64UrlEncoder.Encode(
        SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

    if (decodeChallengeCode != unProtectedCode?.CodeChallenge)
        return Results.BadRequest(new
        {
            error = "invalid code in your challenge session"
        });

    //generate token
    var jwtHandler = new JsonWebTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        // Issuer = "https://localhost:7051",
        // Audience = "https://localhost:7051",
        Expires = DateTime.UtcNow.AddHours(5),
        Claims =new Dictionary<string, object>()
        {
            {"clientId",unProtectedCode.ClientId},
            {"username","arhm"}
        },
        SigningCredentials = 
            new SigningCredentials(KeyAuth.GenerateKey(),SecurityAlgorithms.RsaSha256)
    };
    
    var token = jwtHandler.CreateToken(tokenDescriptor);
    
    return Results.Ok(new
    {
        access_token = token, // Replace with the actual token
        token_type = "Bearer",
        expires_in = 3600, 
    });
}).DisableAntiforgery();

app.MapGet("/user", () =>
{
    return Results.Json(new
    {
        name = "arhm",
        email = "ali@mail"
    });
});

#endregion

#region Internal Endpoints

app.MapGet("/account/login", async (string? returnUrl, HttpResponse response) =>
{
    response.Headers.ContentType = "text/html";
    response.StatusCode = 200;

    await response.WriteAsync($"""

                                       <html>
                                           <body>
                                               <form method='post' action='/account/login?returnUrl={HttpUtility.UrlEncode(returnUrl)}'>
                                                   <label for='username'>Username:</label>
                                                   <input type='text' id='username' name='username' required />
                                                   <br />
                                                   <label for='password'>Password:</label>
                                                   <input type='password' id='password' name='password' required />
                                                   <br />
                                                   <button type='submit'>Login</button>
                                               </form>
                                           </body>
                                       </html>
                               """);
});

app.MapPost("/account/login", async (
    string? returnUrl,
    [FromForm(Name = "userName")] string userName,
    [FromForm(Name = "password")] string password,
    HttpContext context) =>
{
    //todo validate user
    //if user validate

    var claims = new List<Claim>()
    {
        new Claim("username", userName)
    };
    var claimIdentity = new ClaimsIdentity(claims, AuthenticationScheme.Cookie);
    var claimPrincipal = new ClaimsPrincipal(claimIdentity);

    await context.SignInAsync(AuthenticationScheme.Cookie,
        claimPrincipal);

    return Results.LocalRedirect(returnUrl);
}).DisableAntiforgery();

#endregion

app.Run();

public static class AuthenticationScheme
{
    public const string Cookie = "cookie";
}

public class AuthorizationCode
{
    public string ClientId { get; set; }
    public string CodeChallenge { get; set; }
    public string CodeChallengeMethod { get; set; }
    public string ReturnUrl { get; set; }
    public DateTime Expiry { get; set; }
}

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
    
    public static RsaSecurityKey GenerateKey()
    {
        var privateKeyValidation = new RSACryptoServiceProvider();
        privateKeyValidation.FromXmlString(_privateKey);
        return new RsaSecurityKey(privateKeyValidation);
    }
}
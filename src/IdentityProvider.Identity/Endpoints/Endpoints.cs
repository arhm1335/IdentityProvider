using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;

namespace IdentityProvider.Identity.Endpoints;

public static class Endpoints
{
    public static void ConfigureEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var identity = endpoints.MapGroup("api/account/");

        identity.MapPost("register/{username}",
            async (UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, string username) =>
            {
                var user = new IdentityUser()
                {
                    UserName = username,
                    Email = "email@email.email",
                    EmailConfirmed = true,
                    PhoneNumber = "0915654578",
                    PhoneNumberConfirmed = true
                };

                await userManager.CreateAsync(user, "ali@Password123");

                var roleExist = await roleManager.RoleExistsAsync("admin");
                if (!roleExist)
                    await roleManager.CreateAsync(new IdentityRole("admin"));
                
                await userManager.AddToRoleAsync(user, "admin");
            });

        identity.MapGet("login/{username}", async (SignInManager<IdentityUser> signInManager,string username) =>
        {
            var result = await signInManager.PasswordSignInAsync(username, "ali@Password123", true, false);
            if(result.Succeeded)
                return Results.Ok("User Signin Success");

            return Results.BadRequest();
        });
    }
}
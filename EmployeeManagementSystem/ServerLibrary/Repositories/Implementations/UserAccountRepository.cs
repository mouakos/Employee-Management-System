using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations;

public class UserAccountRepository(AppDbContext appDbContext, IOptions<JwtSettings> config) : IUserAccount
{
    #region Public methods declaration

    /// <inheritdoc />
    public async Task<GeneralResponse> CreateAsync(RegisterDto register)
    {
        var checkUser = await FindUserByEmailAsync(register.Email!);
        if (checkUser != null) return new GeneralResponse(false, "User registered already");

        // save register
        var applicationUser = await AddToDataBase(new ApplicationUser
        {
            FullName = register.FullName,
            Email = register.Email,
            Password = BCrypt.Net.BCrypt.HashPassword(register.Password)
        });

        // Check, create and assign role
        var adminRole =
            await appDbContext.SystemRoles.FirstOrDefaultAsync(sysRole => sysRole.Name!.Equals(Constants.Admin));
        if (adminRole is null)
        {
            var createAdminRole = await AddToDataBase(new SystemRole { Name = Constants.Admin });
            await AddToDataBase(new UserRole { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
            return new GeneralResponse(true, "Account created!");
        }

        var userRole =
            await appDbContext.SystemRoles.FirstOrDefaultAsync(sysRole => sysRole.Name!.Equals(Constants.User));
        if (userRole is null)
        {
            var systemRole = await AddToDataBase(new SystemRole { Name = Constants.User });
            await AddToDataBase(new UserRole { RoleId = systemRole.Id, UserId = applicationUser.Id });
        }
        else
        {
            await AddToDataBase(new UserRole { RoleId = userRole.Id, UserId = applicationUser.Id });
        }

        return new GeneralResponse(true, "Account created!");
    }

    /// <inheritdoc />
    public async Task<LoginResponse> RefreshTokenAsync(RefreshTokenDto tokenDto)
    {
        var findToken =
            await appDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token!.Equals(tokenDto.Token));
        if (findToken is null) return new LoginResponse(false, "Refresh token is required");

        // get user details
        var user = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(x => x.Id == findToken.UserId);
        if (user is null)
            return new LoginResponse(false, "Refresh token could not be generated because user not found");

        var userRole = await FindUserRoleAsync(user.Id);
        if (userRole is null) return new LoginResponse(false, "user role not found");
        var systemRole = await FindSystemRoleAsync(userRole.RoleId);
        if (systemRole is null) return new LoginResponse(false, "system role not found");
        var jwtToken = GenerateToken(user, systemRole.Name!);
        var refreshToken = GenerateRefreshToken();

        var updateRefreshToken = await appDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.UserId == user.Id);
        if (updateRefreshToken is null)
            return new LoginResponse(false, "Refresh token could not be generated because user has not signed in");

        updateRefreshToken.Token = refreshToken;
        await appDbContext.SaveChangesAsync();
        return new LoginResponse(true, "Token refreshed successfully", jwtToken, refreshToken);
    }

    /// <inheritdoc />
    public async Task<LoginResponse> SigInAsync(LoginDto login)
    {
        var applicationUser = await FindUserByEmailAsync(login.Email!);
        if (applicationUser == null) return new LoginResponse(false, "User not found");

        // Verify password
        if (!BCrypt.Net.BCrypt.Verify(login.Password, applicationUser.Password))
            return new LoginResponse(false, "Password not valid");

        var userRole = await FindUserRoleAsync(applicationUser.Id);
        if (userRole is null) return new LoginResponse(false, "User role not found");

        var systemRole = await FindSystemRoleAsync(userRole.UserId);
        if (systemRole is null) return new LoginResponse(false, "System role not found");

        var jwtToken = GenerateToken(applicationUser, systemRole.Name!);
        var refreshToken = GenerateRefreshToken();

        // Save the refresh token to the database
        var findUser = await appDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.UserId == applicationUser.Id);
        if (findUser is null)
        {
            await AddToDataBase(new RefreshToken { Token = refreshToken, UserId = applicationUser.Id });
        }
        else
        {
            findUser.Token = refreshToken;
            await appDbContext.SaveChangesAsync();
        }

        return new LoginResponse(true, "Login successfully", jwtToken, refreshToken);
    }

    #endregion

    #region Private methods declaration

    private static string GenerateRefreshToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }

    private async Task<T> AddToDataBase<T>(T model)
    {
        var res = appDbContext.Add(model!);
        await appDbContext.SaveChangesAsync();
        return (T)res.Entity;
    }

    private async Task<SystemRole?> FindSystemRoleAsync(int userId)
    {
        return await appDbContext.SystemRoles.FirstOrDefaultAsync(x => x.Id == userId);
    }

    private async Task<ApplicationUser?> FindUserByEmailAsync(string userEmail)
    {
        return await appDbContext.ApplicationUsers.FirstOrDefaultAsync(x =>
            x.Email!.ToLower().Equals(userEmail.ToLower()));
    }

    private async Task<UserRole?> FindUserRoleAsync(int userId)
    {
        return await appDbContext.UserRoles.FirstOrDefaultAsync(x => x.Id == userId);
    }

    private string GenerateToken(ApplicationUser applicationUser, string systemRoleName)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var userClaims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, applicationUser.Id.ToString()),
            new Claim(ClaimTypes.Name, applicationUser.FullName!),
            new Claim(ClaimTypes.Email, applicationUser.Email!),
            new Claim(ClaimTypes.Role, systemRoleName)
        };

        var token = new JwtSecurityToken(
            config.Value.Issuer,
            config.Value.Audience,
            userClaims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    #endregion
}
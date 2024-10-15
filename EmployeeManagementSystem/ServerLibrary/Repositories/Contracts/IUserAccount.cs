using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ServerLibrary.Repositories.Contracts;

public interface IUserAccount
{
    Task<GeneralResponse> CreateAsync(RegisterDto register);
    Task<LoginResponse> SigInAsync(LoginDto login);
    Task<LoginResponse> RefreshTokenAsync(RefreshTokenDto refreshTokenDto);
}
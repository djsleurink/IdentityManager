using System.Security.Claims;
using IdentityManager.Models;

namespace IdentityManager.Services
{
    public interface IIdentityManager
    {
        Dictionary<string, string> ClaimTypes { get; init; }
        Dictionary<string, string> Roles { get; }
        Task<ResponseModel> CreateRole(string name);
        Task<ResponseModel> CreateUser(string userName, string name, string email, string password);
        Task<ResponseModel> DeleteRole(string id);
        Task<ResponseModel> DeleteUser(string id);
        Task<IEnumerable<Role>> GetRolesAsync(string? filter = null);
        Task<User> GetUser(string id);
        Task<IEnumerable<User>> GetUsersAsync(string? filter = null);
        Task<IEnumerable<Role>> GetUserRolesAsync(string userId);
        Task<IEnumerable<Claim>> GetUserClaimsAsync(string userId);
        Task<ResponseModel> ResetPassword(string id, string password, string verify);
        Task<ResponseModel> UpdateRole(string id, string name, List<KeyValuePair<string, string>> claims);
        Task<ResponseModel> UpdateUser(string id, string email, bool locked, string[] roles, List<KeyValuePair<string, string>> claims);
    }
}
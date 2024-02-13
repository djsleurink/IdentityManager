using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Reflection;
using IdentityManager.Models;

namespace IdentityManager.Services
{
    /// <summary>
    /// Provide all the CRUD operations against the ASP.NET Core Identity tables.
    /// </summary>
    public class IdentityManager<TIdentityUser, TIdentityRole> : IIdentityManager where TIdentityUser : IdentityUser, new() where TIdentityRole : IdentityRole, new()
    {
        private readonly UserManager<TIdentityUser> _userManager;
        private readonly RoleManager<TIdentityRole> _roleManager;
        /// <summary>
        /// Contains an updated list of all Roles in the database.
        /// </summary>
        public Dictionary<string, string> Roles { get; private set; }
        public Dictionary<string, string> ClaimTypes { get; init; }

        /// <summary>
        /// Manager constructor that sets the userManager, roleManager, and ClaimTypes.
        /// </summary>
        /// <param name="userManager">Exposes CRUD operations for users from the Microsoft.Extensions.Identity.Core assembly in the Microsoft.AspNetCore.Identity namespace.</param>
        /// <param name="roleManager">Exposes CRUD operations for roles from the Microsoft.Extensions.Identity.Core assembly in the Microsoft.AspNetCore.Identity namespace.</param>
        public IdentityManager(UserManager<TIdentityUser> userManager, RoleManager<TIdentityRole> roleManager)
        {
            ArgumentNullException.ThrowIfNull(roleManager);
            ArgumentNullException.ThrowIfNull(userManager);

            _userManager = userManager;
            _roleManager = roleManager;

            // Set all the roles in the database, ordered by Name ascending.
            Roles = roleManager.Roles?.OrderBy(r => r.Name).ToDictionary(r => r.Id, r => r.Name ?? string.Empty) ?? [];

            var fieldInfo = typeof(ClaimTypes).GetFields(BindingFlags.Static | BindingFlags.Public);

            // Set all the claim types as defined in the System.Security.Claims constants.
            ClaimTypes = fieldInfo.ToDictionary(i => i.Name, i => i.GetValue(null) as string ?? string.Empty);
        }


        /// <summary>
        /// Returns a collection of users from the database.
        /// </summary>
        /// <param name="filter">When provided, filter the users based on partial matches of email, and username.</param>
        /// <returns>A collection of User objects.</returns>
        public async Task<IEnumerable<User>> GetUsersAsync(string? filter = null)
        {
            filter = filter?.Trim();

            // Get all users, including roles, and claims, from the database.

            var users = _userManager.Users;

            // Filter the user list, and order by username ascending.
            var query = users.Where(u =>
                string.IsNullOrWhiteSpace(filter) || (u.Email != null && u.Email.Contains(filter)) ||
                string.IsNullOrWhiteSpace(filter) || (u.UserName != null && u.UserName.Contains(filter))
            ).OrderBy(u => u.UserName);
            // Execute the query and set properties.
            List<User> result = [];
            foreach (var u in query.ToArray())
            {
                var roles = await _userManager.GetRolesAsync(u);
                var claims = await _userManager.GetClaimsAsync(u);
                result.Add(new User
                {
                    Id = u.Id,
                    Email = u.Email,
                    LockedOut = u.LockoutEnd == null ? string.Empty : "Yes",
                    Roles = roles,
                    //Key/Value props not camel cased (https://github.com/dotnet/corefx/issues/41309)
                    Claims = claims.Select(c => new KeyValuePair<string, string>(ClaimTypes.Single(x => x.Value == c.Type).Key, c.Value)),
                    DisplayName = claims?.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Name)?.Value,
                    UserName = u.UserName
                });
            }
            return result.ToList();
        }

        /// <summary>
        /// Create a user in the database.
        /// </summary>
        /// <param name="userName">Username for the account.</param>
        /// <param name="name">Name of the user.</param>
        /// <param name="email">Email of the user.</param>
        /// <param name="password">Password for the user.</param>
        /// <returns>Response object.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments are not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<ResponseModel> CreateUser(string userName, string name, string email, string password)
        {
            if (string.IsNullOrWhiteSpace(userName))
                throw new ArgumentNullException(nameof(userName), "The argument userName cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The argument name cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(email))
                throw new ArgumentNullException(nameof(email), "The argument email cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException(nameof(password), "The argument password cannot be null or empty.");

            var user = new TIdentityUser() { Email = email, UserName = userName };

            // Create user.
            var result = await _userManager.CreateAsync(user, password);
            ResponseModel response;
            if (result.Succeeded)
            {
                if (name != null)
                    await _userManager.AddClaimAsync(user, new Claim(System.Security.Claims.ClaimTypes.Name, name));
                response = ResponseModel.SuccessResponse(string.Empty, result);
            }
            else
            {
                response = ResponseModel.FailureResponse(result.Errors.GetAllMessages());
            }


            return response;
        }

        /// <summary>
        /// Get user by ID.
        /// </summary>
        /// <param name="id">ID of the user.</param>
        /// <returns>Returns the ApplicationUser object.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments are not provided, an ArgumentNullException will be thrown.</exception>
        /// <exception cref="Exception">Throws an exception when the user is not found.</exception>
        public async Task<User> GetUser(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
                throw new ArgumentNullException(nameof(id), "The argument id cannot be null or empty.");

            // Gets the user.
            var user = await _userManager.FindByIdAsync(id) ?? throw new Exception("User not found.");

            // Get the current user roles.
            var userRoles = await _userManager.GetRolesAsync(user);

            // Get the current user claims.
            var userClaims = await _userManager.GetClaimsAsync(user);
            return new User()
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                Claims = userClaims.Select(claim => KeyValuePair.Create(claim.Type, claim.Value)).ToList(),
                Roles = userRoles.ToList(),
                LockedOut = user.LockoutEnd?.ToString(),
                LockoutEnd = user.LockoutEnd,
            };
        }

        /// <summary>
        /// Get a list of roles for a specific user
        /// </summary>
        /// <param name="userId">ID of the user.</param>
        /// <returns></returns>
        /// <exception cref="Exception">When the user cannot be found an Exception will be thrown</exception>
        /// <returns>List of roles.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments is not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<IEnumerable<Role>> GetUserRolesAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentNullException(nameof(userId), $"The argument {userId} cannot be null or empty.");

            // Gets the user.
            var user = await _userManager.FindByIdAsync(userId) ?? throw new Exception("User not found.");
            var roles = await _userManager.GetRolesAsync(user);
            if (!roles.Any())
            {
                return Enumerable.Empty<Role>();
            }

            // Get the current user roles.
            return roles.Select(role => new Role() { Name = role }).ToList();
        }

        /// <summary>
        /// Get a list of claims for a specific user
        /// </summary>
        /// <param name="userId">ID of the user.</param>
        /// <returns></returns>
        /// <exception cref="Exception">When the user cannot be found an Exception will be thrown</exception>
        /// <returns>List of claims.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments is not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<IEnumerable<Claim>> GetUserClaimsAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentNullException(nameof(userId), $"The argument {userId} cannot be null or empty.");

            // Gets the user.
            var user = await _userManager.FindByIdAsync(userId) ?? throw new Exception("User not found.");

            // Get the current user roles.
            return await _userManager.GetClaimsAsync(user);
        }

        /// <summary>
        /// Update the user.
        /// </summary>
        /// <param name="id">ID of the user.</param>
        /// <param name="email">Email of the user.</param>
        /// <param name="locked">Weather or not the user account is locked.</param>
        /// <param name="roles">List of roles the user should be added to.</param>
        /// <param name="claims">List of claims the user should be added to.</param>
        /// <returns>Response object.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments is not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<ResponseModel> UpdateUser(string id, string email, bool locked, string[] roles, List<KeyValuePair<string, string>> claims)
        {
            if (string.IsNullOrWhiteSpace(id))
                throw new ArgumentNullException(nameof(id), "The argument id cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(email))
                throw new ArgumentNullException(nameof(email), "The argument email cannot be null or empty.");

            if (roles == null)
                throw new ArgumentNullException(nameof(roles), "The argument roles cannot be null.");

            ResponseModel response;

            try
            {
                // Gets the user by ID.
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                    response = ResponseModel.FailureResponse("User not found.");

                // Update only the updatable properties.
                user!.Email = email;
                user.LockoutEnd = locked ? DateTimeOffset.MaxValue : default(DateTimeOffset?);

                // Update user.
                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    response = ResponseModel.SuccessResponse($"Updated user {user.UserName}", user);

                    // Get the current user roles.
                    var userRoles = await _userManager.GetRolesAsync(user);

                    // Add specified user roles.
                    foreach (string role in roles.Except(userRoles))
                        await _userManager.AddToRoleAsync(user, role);

                    // Remove any roles, not specified, from the user. 
                    foreach (string role in userRoles.Except(roles))
                        await _userManager.RemoveFromRoleAsync(user, role);

                    // Get the current user claims.
                    var userClaims = await _userManager.GetClaimsAsync(user);

                    // Add specified user claims.
                    foreach (var kvp in claims.Where(a => !userClaims.Any(b => ClaimTypes[a.Key] == b.Type && a.Value == b.Value)))
                        await _userManager.AddClaimAsync(user, new Claim(ClaimTypes[kvp.Key], kvp.Value));

                    // Remove any claims, not specified, from the user. 
                    foreach (var claim in userClaims.Where(a => !claims.Any(b => a.Type == ClaimTypes[b.Key] && a.Value == b.Value)))
                        await _userManager.RemoveClaimAsync(user, claim);
                }
                else
                    response = ResponseModel.FailureResponse(result.Errors.GetAllMessages());

                response.Success = result.Succeeded;
            }
            catch (Exception ex)
            {
                response = ResponseModel.FailureResponse($"Failure updating user {id}: {ex.Message}");
            }

            return response;
        }

        /// <summary>
        /// Delete user by ID.
        /// </summary>
        /// <param name="id">ID of the user.</param>
        /// <returns>Response object.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments are not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<ResponseModel> DeleteUser(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
                throw new ArgumentNullException(nameof(id), "The argument id cannot be null or empty.");

            ResponseModel response;

            try
            {
                // Get the user.
                var user = await _userManager.FindByIdAsync(id);

                if (user == null)
                    response = ResponseModel.FailureResponse("User not found.");

                // Delete the user.
                var result = await _userManager.DeleteAsync(user!);

                if (result.Succeeded)
                    response = ResponseModel.SuccessResponse($"Deleted user {user!.UserName}.", result);
                else
                    response = ResponseModel.FailureResponse(result.Errors.GetAllMessages());

                response.Success = result.Succeeded;
            }
            catch (Exception ex)
            {
                response = ResponseModel.FailureResponse($"Failure deleting user {id}: {ex.Message}");
            }

            return response;
        }

        /// <summary>
        /// Reset user password.
        /// </summary>
        /// <param name="id">ID of the user.</param>
        /// <param name="password">Password for the user.</param>
        /// <param name="verify">Password for verification purposes.</param>
        /// <returns>Response object.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments are not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<ResponseModel> ResetPassword(string id, string password, string verify)
        {
            if (string.IsNullOrWhiteSpace(id))
                throw new ArgumentNullException(nameof(id), "The argument id cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException(nameof(password), "The argument password cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(verify))
                throw new ArgumentNullException(nameof(verify), "The argument verify cannot be null or empty.");

            ResponseModel response;

            try
            {
                if (password != verify)
                    response = ResponseModel.FailureResponse("Passwords entered do not match.");

                // Get the user.
                var user = await _userManager.FindByIdAsync(id);

                if (user == null)
                    response = ResponseModel.FailureResponse("User not found.");

                // Delete existing password if it exists.
                if (await _userManager.HasPasswordAsync(user!))
                    await _userManager.RemovePasswordAsync(user!);

                // Add new password for the user.
                var result = await _userManager.AddPasswordAsync(user!, password);

                if (result.Succeeded)
                {
                    response = ResponseModel.SuccessResponse($"Password reset for {user!.UserName}.", user);
                }
                else
                    response = ResponseModel.FailureResponse(result.Errors.GetAllMessages());
            }
            catch (Exception ex)
            {
                response = ResponseModel.FailureResponse($"Failed password reset for user {id}: {ex.Message}");
            }

            return response;
        }

        /// <summary>
        /// Get user roles.
        /// </summary>
        /// <param name="filter">When provided, filter the roles based on partial matches of role name.</param>
        /// <returns>A collection of role objects.</returns>
        public async Task<IEnumerable<Role>> GetRolesAsync(string? filter = null)
        {
            // Get all roles, including claims, from the database.
            var roles = _roleManager.Roles;

            // Filter role list, and order by name ascending.
            var query = roles.Where(r =>
                string.IsNullOrWhiteSpace(filter) || (r.Name != null && r.Name.Contains(filter))
            ).OrderBy(r => r.Name); ;

            // Execute the query and set properties.
            var result = new List<Role>();
            foreach (var role in query.ToArray())
            {
                var claims = await _roleManager.GetClaimsAsync(role);
                var r = new Role
                {
                    Id = role.Id,
                    Name = role.Name,
                    //Key/Value props not camel cased (https://github.com/dotnet/corefx/issues/41309)
                    Claims = claims.Select(c => new KeyValuePair<string, string>(ClaimTypes.Single(x => x.Value == c.Type).Key, c.Value))
                };
                result.Add(r);
            }
            return result;
        }



        /// <summary>
        /// Create role.
        /// </summary>
        /// <param name="name">Role name.</param>
        /// <returns>Response object.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments are not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<ResponseModel> CreateRole(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The argument name cannot be null or empty.");

            ResponseModel response;
            var role = new TIdentityRole
            {
                Name = name
            };
            // Create role.
            var result = await _roleManager.CreateAsync(role);

            if (!result.Succeeded)
            {
                response = ResponseModel.FailureResponse(result.Errors.GetAllMessages());
            }

            response = ResponseModel.SuccessResponse(string.Empty, null);

            // Update the current collection of roles in the database.
            Roles = _roleManager.Roles.OrderBy(r => r.Name).ToDictionary(r => r.Id, r => r.Name ?? string.Empty);

            return response;
        }

        /// <summary>
        /// Update role.
        /// </summary>
        /// <param name="id">ID of the role.</param>
        /// <param name="name">Name of the role.</param>
        /// <param name="claims">List of claims the role should be added to.</param>
        /// <returns>Response object.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments are not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<ResponseModel> UpdateRole(string id, string name, List<KeyValuePair<string, string>> claims)
        {
            if (string.IsNullOrWhiteSpace(id))
                throw new ArgumentNullException(nameof(id), "The argument id cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name), "The argument name cannot be null or empty.");

            ResponseModel response;

            try
            {
                // Get role.
                var role = await _roleManager.FindByIdAsync(id);

                if (role == null)
                    response = ResponseModel.FailureResponse("Role not found.");

                // Update updatable properties.
                role!.Name = name;

                // Update role.
                var result = await _roleManager.UpdateAsync(role);

                if (result.Succeeded)
                {
                    response = ResponseModel.SuccessResponse($"Updated role {role.Name}", role);

                    // Get the current role claims.
                    var roleClaims = await _roleManager.GetClaimsAsync(role);

                    // Add specified role claims.
                    foreach (var kvp in claims.Where(a => !roleClaims.Any(b => ClaimTypes[a.Key] == b.Type && a.Value == b.Value)))
                        await _roleManager.AddClaimAsync(role, new Claim(ClaimTypes[kvp.Key], kvp.Value));

                    // Remove any claims, not specified, from the role.
                    foreach (var claim in roleClaims.Where(a => !claims.Any(b => a.Type == ClaimTypes[b.Key] && a.Value == b.Value)))
                        await _roleManager.RemoveClaimAsync(role, claim);
                }
                else
                    response = ResponseModel.FailureResponse(result.Errors.GetAllMessages());

                response.Success = result.Succeeded;
            }
            catch (Exception ex)
            {
                response = ResponseModel.FailureResponse($"Failure updating role {id}: {ex.Message}");
            }

            // Update the current collection of roles in the database.
            Roles = _roleManager.Roles.OrderBy(r => r.Name).ToDictionary(r => r.Id, r => r.Name ?? string.Empty);

            return response;
        }

        /// <summary>
        /// Delete role.
        /// </summary>
        /// <param name="id">ID of the role.</param>
        /// <returns>Response object.</returns>
        /// <exception cref="ArgumentNullException">When any of the arguments are not provided, an ArgumentNullException will be thrown.</exception>
        public async Task<ResponseModel> DeleteRole(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
                throw new ArgumentNullException(nameof(id), "The argument id cannot be null or empty.");

            ResponseModel response;

            try
            {
                // Get role.
                var role = await _roleManager.FindByIdAsync(id);

                if (role == null)
                    response = ResponseModel.SuccessResponse("Role not found.", null);

                // Delete role.
                var result = await _roleManager.DeleteAsync(role!);

                if (result.Succeeded)
                    response = ResponseModel.SuccessResponse($"Deleted role {role!.Name}.", null);
                else
                    response = ResponseModel.FailureResponse(result.Errors.GetAllMessages());

                response.Success = result.Succeeded;
            }
            catch (Exception ex)
            {
                response = ResponseModel.FailureResponse($"Failure deleting role {id}: {ex.Message}");
            }

            // Update the current collection of roles in the database.
            Roles = _roleManager.Roles.OrderBy(r => r.Name).ToDictionary(r => r.Id, r => r.Name ?? string.Empty);

            return response;
        }
    }
}
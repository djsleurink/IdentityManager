using IdentityManager.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace IdentityManager
{
    /// <summary>
    /// Provides a means to add the IdentityManager to the ServiceCollection
    /// </summary>
    public static class DependencyInjection
    {
        /// <summary>
        /// Adds the identity manager, user manager and role manager to the service collection (when necessary)
        /// </summary>
        /// <typeparam name="TIdentityUser">The user model used as an IdentityUser within the system, can be IdentityUser</typeparam>
        /// <typeparam name="TIdentityRole">The role model used as an IdentityRole within the system, can be IdentityRole</typeparam>
        /// <param name="serviceCollection">The service collection</param>
        /// <returns></returns>
        public static IServiceCollection AddIdentityManager<TIdentityUser, TIdentityRole>(this IServiceCollection serviceCollection) where TIdentityUser : IdentityUser, new() where TIdentityRole : IdentityRole, new()
        {
            serviceCollection.TryAddScoped<UserManager<TIdentityUser>>();
            serviceCollection.TryAddScoped<RoleManager<TIdentityRole>>();
            serviceCollection.TryAddScoped<IIdentityManager, IdentityManager<TIdentityUser, TIdentityRole>>();
            return serviceCollection;
        }
    }
}

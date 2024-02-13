using System.ComponentModel.DataAnnotations;

namespace IdentityManager.ViewModels
{
    public class EditUserViewModel
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
    }
}
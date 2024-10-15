using System.ComponentModel.DataAnnotations;

namespace BaseLibrary.DTOs;

public class AccountBaseDto
{
    [DataType(DataType.EmailAddress)]
    [Required]
    [EmailAddress]
    public string? Email { get; set; }

    [DataType(DataType.Password)]
    [Required]
    public string? Password { get; set; }
}
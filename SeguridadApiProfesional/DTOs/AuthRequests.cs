namespace SeguridadApiProfesional.DTOs
{
    public class AuthRequests
    {
    }
    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class RegistroRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}

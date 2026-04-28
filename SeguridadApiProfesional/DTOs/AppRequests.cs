namespace SeguridadApiProfesional.DTOs
{
    public class AppRequests
    {
    }

    public class CrearPostRequest
    {
        public string Title { get; set; }
        public string BodyContent { get; set; }
    }

    public class BloqueoRequest
    {
        public int UserId { get; set; }
        public bool Bloquear { get; set; }
    }

    public class CambiarRolRequest
    {
        public int UserId { get; set; }
        public string Username { get; set; }
        public string NuevoRol { get; set; } // Aquí recibiremos 'admin' o 'user'
    }
}

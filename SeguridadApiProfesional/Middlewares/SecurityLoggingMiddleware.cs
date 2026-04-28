using Microsoft.AspNetCore.Http;
using Npgsql;
using Dapper;
using System.Threading.Tasks;

namespace SeguridadApiProfesional.Middlewares
{
    public class SecurityLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly string _connectionString;

        public SecurityLoggingMiddleware(RequestDelegate next, IConfiguration config)
        {
            _next = next; // _next representa el siguiente paso en la tubería de tu API
            _connectionString = config.GetConnectionString("DefaultConnection");
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // 1. Dejamos que la petición siga su curso normal hacia los controladores
            await _next(context);

            // 2. Cuando la respuesta viene de regreso, revisamos si fue rechazada por seguridad
            if (context.Response.StatusCode == StatusCodes.Status401Unauthorized ||
                context.Response.StatusCode == StatusCodes.Status403Forbidden)
            {
                await RegistrarAccesoDenegado(context);
            }
        }

        private async Task RegistrarAccesoDenegado(HttpContext context)
        {
            string ip = context.Connection.RemoteIpAddress?.ToString() ?? "0.0.0.0";
            string endpoint = context.Request.Path.ToString();
            string userAgent = context.Request.Headers["User-Agent"].ToString() ?? "Desconocido";

            // Si el usuario intentó entrar a una zona Admin pero es solo User, su nombre estará aquí.
            // Si ni siquiera mandó Token, será "Anónimo".
            string username = context.User.Identity?.IsAuthenticated == true
                ? context.User.Identity.Name
                : "Anónimo";

            string accion = context.Response.StatusCode == 401
                ? "Bloqueo: Intento de acceso sin Token válido"
                : "Bloqueo: Intento de evasión de privilegios (Falta Rol)";

            string sql = @"
                INSERT INTO security_logs (username, action, severity_level, endpoint, user_agent, ip_address) 
                VALUES (@u, @a, 'CRITICAL', @end, @ua, @ip)";

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                // Usamos ExecuteAsync para que no bloquee el hilo principal del servidor
                await conn.ExecuteAsync(sql, new { u = username, a = accion, end = endpoint, ua = userAgent, ip = ip });
            }
        }
    }
}
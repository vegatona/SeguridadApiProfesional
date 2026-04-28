using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dapper;
using Npgsql;
using SeguridadApiProfesional.DTOs;

namespace SeguridadApiProfesional.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "admin")] // 🛡️ Solo los Tokens con el Claim de 'admin' pueden pasar
    public class AdminController : ControllerBase
    {
        private readonly string _connectionString;

        public AdminController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }

        // GET: api/admin/dashboard
        [HttpGet("dashboard")]
        public IActionResult GetDashboard()
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                // En un solo endpoint mandamos tanto los usuarios como los logs
                var sqlUsers = "SELECT user_id, username, role, failed_login_attempts, account_locked_until FROM app_users ORDER BY user_id ASC";
                var sqlLogs = "SELECT log_id, username, action, ip_address, created_at FROM security_logs ORDER BY created_at DESC LIMIT 50";

                var users = conn.Query<dynamic>(sqlUsers);
                var logs = conn.Query<dynamic>(sqlLogs);

                // Angular recibirá esto como un objeto con dos arreglos adentro
                return Ok(new { usuarios = users, logs = logs });
            }
        }

        // POST: api/admin/bloquear
        [HttpPost("bloquear")]
        public IActionResult CambiarEstadoBloqueo([FromBody] BloqueoRequest request)
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                string sql = request.Bloquear
                    ? "UPDATE app_users SET account_locked_until = @fecha WHERE user_id = @id"
                    : "UPDATE app_users SET account_locked_until = NULL, failed_login_attempts = 0 WHERE user_id = @id";

                conn.Execute(sql, new
                {
                    id = request.UserId,
                    fecha = request.Bloquear ? (DateTime?)DateTime.Now.AddYears(100) : null
                });

                return Ok(new { message = request.Bloquear ? "Usuario bloqueado" : "Usuario desbloqueado" });
            }
        }

        // POST: api/admin/cambiar-rol
        [HttpPost("cambiar-rol")]
        public IActionResult CambiarRol([FromBody] CambiarRolRequest request)
        {
            // 🛡️ 1. Evitar que el admin se quite el rol a sí mismo
            if (request.Username == User.Identity?.Name && request.NuevoRol != "admin")
            {
                return BadRequest("Por seguridad, no puedes quitarte el rol de administrador a ti mismo.");
            }

            // 🛡️ 2. Validar que el rol sea uno de los permitidos en el sistema
            if (request.NuevoRol != "admin" && request.NuevoRol != "user")
            {
                return BadRequest("El rol especificado no es válido. Usa 'admin' o 'user'.");
            }

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                string sql = "UPDATE app_users SET role = @rol WHERE user_id = @id";
                conn.Execute(sql, new { rol = request.NuevoRol, id = request.UserId });

                return Ok(new { message = $"El rol del usuario {request.Username} ha sido actualizado a '{request.NuevoRol}'." });
            }
        }

        // DELETE: api/admin/usuario/5?username=nombre
        [HttpDelete("usuario/{id}")]
        public IActionResult EliminarUsuario(int id, [FromQuery] string username)
        {
            // 🛡️ Evitar que el admin se borre a sí mismo leyendo su nombre del Token
            if (username == User.Identity?.Name)
                return BadRequest("No puedes eliminar tu propia cuenta de administrador.");

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                conn.Execute("DELETE FROM app_users WHERE user_id = @id", new { id });
                return Ok(new { message = "Usuario eliminado exitosamente" });
            }
        }

        // DELETE: api/admin/logs
        [HttpDelete("logs")]
        public IActionResult LimpiarLogs()
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                conn.Execute("DELETE FROM security_logs");
                return Ok(new { message = "Bitácora de seguridad limpiada" });
            }
        }
    }
}
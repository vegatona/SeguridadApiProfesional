using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dapper;
using Npgsql;
using SeguridadApiProfesional.DTOs;

namespace SeguridadApiProfesional.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "admin")]
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
            try
            {
                using (var conn = new NpgsqlConnection(_connectionString))
                {
                    // Consulta de usuarios
                    var sqlUsers = "SELECT user_id, username, role, failed_login_attempts, account_locked_until FROM app_users ORDER BY user_id ASC";

                    // Consulta de logs (Verifica el nombre de la tabla en tu DB)
                    var sqlLogs = "SELECT log_id, username, action, ip_address, created_at FROM security_logs ORDER BY created_at DESC LIMIT 50";

                    var users = conn.Query<dynamic>(sqlUsers);
                    var logs = conn.Query<dynamic>(sqlLogs);

                    return Ok(new { usuarios = users, logs = logs });
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "Error al obtener datos del dashboard", detalle = ex.Message });
            }
        }

        [HttpPost("bloquear")]
        public IActionResult CambiarEstadoBloqueo([FromBody] BloqueoRequest request)
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                // Si bloqueamos, ponemos fecha de 100 años al futuro, si no, NULL
                string sql = request.Bloquear
                    ? "UPDATE app_users SET account_locked_until = @fecha WHERE user_id = @id"
                    : "UPDATE app_users SET account_locked_until = NULL, failed_login_attempts = 0 WHERE user_id = @id";

                conn.Execute(sql, new
                {
                    id = request.UserId,
                    fecha = request.Bloquear ? (DateTime?)DateTime.Now.AddYears(100) : null
                });

                return Ok(new { message = request.Bloquear ? "Usuario bloqueado correctamente" : "Usuario desbloqueado correctamente" });
            }
        }

        [HttpPost("cambiar-rol")]
        public IActionResult CambiarRol([FromBody] CambiarRolRequest request)
        {
            if (request.Username == User.Identity?.Name && request.NuevoRol != "admin")
            {
                return BadRequest(new { message = "Por seguridad, no puedes quitarte el rol de admin a ti mismo." });
            }

            if (request.NuevoRol != "admin" && request.NuevoRol != "user")
            {
                return BadRequest(new { message = "Rol no válido." });
            }

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                string sql = "UPDATE app_users SET role = @rol WHERE user_id = @id";
                conn.Execute(sql, new { rol = request.NuevoRol, id = request.UserId });

                return Ok(new { message = $"Rol actualizado a '{request.NuevoRol}' para {request.Username}." });
            }
        }

        [HttpDelete("usuario/{id}")]
        public IActionResult EliminarUsuario(int id, [FromQuery] string username)
        {
            if (username == User.Identity?.Name)
                return BadRequest(new { message = "No puedes eliminar tu propia cuenta." });

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                conn.Execute("DELETE FROM app_users WHERE user_id = @id", new { id });
                return Ok(new { message = "Usuario eliminado exitosamente." });
            }
        }
    }
}
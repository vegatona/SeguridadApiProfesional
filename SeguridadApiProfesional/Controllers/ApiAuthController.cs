using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Dapper;
using Npgsql;
using BCrypt.Net;
using SeguridadApiProfesional.DTOs; // 👈 Aquí conectamos con la carpeta DTOs
using Microsoft.AspNetCore.RateLimiting;

namespace SeguridadApiProfesional.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly string _connectionString;
        private readonly IConfiguration _config;

        public AuthController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
            _config = configuration;
        }

        // 🛡️ REGISTRO DE USUARIOS
        [EnableRateLimiting("FrenoLogin")]
        [HttpPost("register")]
        public IActionResult Register([FromBody] RegistroRequest request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                string sql = "INSERT INTO app_users (username, password_hash, role) VALUES (@u, @p, 'user')";
                try
                {
                    conn.Execute(sql, new { u = request.Username, p = passwordHash });
                    return Ok(new { message = "Usuario registrado exitosamente" });
                }
                catch (PostgresException ex) when (ex.SqlState == "23505")
                {
                    return BadRequest("El nombre de usuario ya existe");
                }
            }
        }

        // 🛡️ LOGIN CON JWT Y BLOQUEO DE CUENTA
        [EnableRateLimiting("FrenoLogin")]
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            using (var conn = new NpgsqlConnection(_connectionString))
            {
                // 1. Buscamos al usuario usando Dapper
                string sqlUser = "SELECT * FROM app_users WHERE username = @u";
                var user = conn.QuerySingleOrDefault<dynamic>(sqlUser, new { u = request.Username });

                if (user == null)
                {
                    // 🟡 ADVERTENCIA: Alguien intenta adivinar usuarios
                    RegistrarLog(request.Username, "Intento de login: Usuario inexistente", "WARNING", conn);
                    return Unauthorized("Credenciales inválidas");
                }

                // 2. Verificar si está bloqueado (Defensa A07)
                if (user.account_locked_until != null && user.account_locked_until > DateTime.Now)
                {
                    // 🟡 ADVERTENCIA: Intento de entrar a una cuenta castigada
                    RegistrarLog(request.Username, "Login rechazado: Cuenta bloqueada", "WARNING", conn);
                    return StatusCode(403, $"Cuenta bloqueada hasta {user.account_locked_until}");
                }

                // 3. Validar contraseña con BCrypt
                bool esValida = BCrypt.Net.BCrypt.Verify(request.Password, user.password_hash);

                if (esValida)
                {
                    // Resetear intentos fallidos
                    conn.Execute("UPDATE app_users SET failed_login_attempts = 0, account_locked_until = NULL WHERE user_id = @id", new { id = user.user_id });

                    // 🟢 INFO: Todo en orden
                    RegistrarLog(request.Username, "Inicio de sesión exitoso (API)", "INFO", conn);

                    // Generar Token JWT
                    string token = GenerarTokenJWT(user);
                    return Ok(new { token, username = user.username, role = user.role });
                }
                else
                {
                    // Manejar intento fallido
                    int nuevosIntentos = user.failed_login_attempts + 1;
                    DateTime? bloqueo = nuevosIntentos >= 3 ? DateTime.Now.AddMinutes(5) : null;

                    conn.Execute("UPDATE app_users SET failed_login_attempts = @i, account_locked_until = @b WHERE user_id = @id",
                                 new { i = nuevosIntentos, b = bloqueo, id = user.user_id });

                    // Lógica inteligente para la bitácora
                    if (nuevosIntentos >= 3)
                    {
                        // 🔴 CRÍTICO: Acaban de bloquear la cuenta (Posible ataque)
                        RegistrarLog(request.Username, "Fuerza bruta detectada. Cuenta bloqueada.", "CRITICAL", conn);
                    }
                    else
                    {
                        // 🟡 ADVERTENCIA: Solo se equivocó de contraseña
                        RegistrarLog(request.Username, $"Login fallido: Intento {nuevosIntentos}", "WARNING", conn);
                    }

                    return Unauthorized("Credenciales inválidas");
                }
            }
        }

        // 🛡️ GENERACIÓN DEL TOKEN (LA "LLAVE" PARA ANGULAR)
        private string GenerarTokenJWT(dynamic user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["Jwt:Key"]);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.username.ToString()),
                    new Claim(ClaimTypes.Role, user.role.ToString()),
                    new Claim("UserId", user.user_id.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(4),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        // 🛡️ AUDITORÍA (LOGS)
        private void RegistrarLog(string username, string accion, string severidad, NpgsqlConnection conn)
        {
            // Capturamos los datos automáticos de la petición web
            string ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "0.0.0.0";
            string userAgent = HttpContext.Request.Headers["User-Agent"].ToString(); // 👈 Atrapa el navegador/dispositivo
            string endpoint = HttpContext.Request.Path.ToString();                   // 👈 Atrapa la URL (/api/auth/login)

            string sql = @"
            INSERT INTO security_logs (username, action, severity_level, endpoint, user_agent, ip_address) 
            VALUES (@u, @a, @sev, @end, @ua, @ip)";

            conn.Execute(sql, new
            {
                u = username,
                a = accion,
                sev = severidad,
                end = endpoint,
                ua = userAgent,
                ip = ip
            });
        }
    }
}
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dapper;
using Npgsql;
using SeguridadApiProfesional.DTOs;

namespace SeguridadApiProfesional.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // 🛡️ Candado global: Nadie entra sin su Token JWT
    public class PostsController : ControllerBase
    {
        private readonly string _connectionString;

        public PostsController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }

        // GET: api/posts?pagina=1&cantidad=10
        [HttpGet]
        public IActionResult GetPosts([FromQuery] int pagina = 1, [FromQuery] int cantidad = 10)
        {
            // 🛡️ Reglas de seguridad para evitar abusos
            if (pagina < 1) pagina = 1;
            if (cantidad < 1) cantidad = 10;
            if (cantidad > 50) cantidad = 50; // Evita que alguien pida un millón de posts de golpe

            int offset = (pagina - 1) * cantidad;

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                // Añadimos LIMIT y OFFSET a la consulta
                string sql = @"
            SELECT p.post_id, p.title, p.body_content, p.published_at, u.username as author_name 
            FROM app_posts p
            INNER JOIN app_users u ON p.author_id = u.user_id
            ORDER BY p.published_at DESC
            LIMIT @Limit OFFSET @Offset";

                var posts = conn.Query<dynamic>(sql, new { Limit = cantidad, Offset = offset });

                // Devolvemos un objeto estructurado para que Angular sepa en qué página está
                return Ok(new
                {
                    paginaActual = pagina,
                    resultadosPorPagina = cantidad,
                    publicaciones = posts
                });
            }
        }

        // POST: api/posts
        [HttpPost]
        public IActionResult CrearPost([FromBody] CrearPostRequest request)
        {
            // 🛡️ Extraemos el ID del usuario de forma segura desde los Claims del JWT
            var userIdString = User.FindFirst("UserId")?.Value;

            if (!int.TryParse(userIdString, out int authorId))
                return Unauthorized("No se pudo identificar al usuario en el token.");

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                string sql = "INSERT INTO app_posts (author_id, title, body_content) VALUES (@auth, @tit, @body)";
                conn.Execute(sql, new { auth = authorId, tit = request.Title, body = request.BodyContent });

                return Ok(new { message = "Publicación creada con éxito." });
            }
        }
    }
}
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Diagnostics;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
// 🛡️ ENSEÑARLE A SWAGGER A USAR TOKENS JWT
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Pega tu Token JWT aquí abajo."
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});
// 🛡️ 1. Configurar CORS (Vital para Angular)
builder.Services.AddCors(options => {
    options.AddPolicy("AllowAngular", policy => {
        policy.WithOrigins("http://localhost:4200") // Puerto por defecto de Angular
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// 🛡️ 2. Configurar Autenticación JWT
var jwtKey = builder.Configuration["Jwt:Key"];
var keyBytes = Encoding.ASCII.GetBytes(jwtKey);

builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

// 🛡️ 1. CONFIGURAR RATE LIMITING
builder.Services.AddRateLimiter(options =>
{
    // Cuando el límite se excede, el servidor devuelve un Error 429 (Too Many Requests)
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Creamos una política específica llamada "FrenoLogin"
    options.AddFixedWindowLimiter("FrenoLogin", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1); // Ventana de tiempo: 1 minuto
        opt.PermitLimit = 5;                  // Máximo 5 intentos permitidos en esa ventana
        opt.QueueLimit = 0;                   // Si se pasa de 5, se rechaza de inmediato (sin hacer cola)
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// 🛡️ PARACAÍDAS GLOBAL: MANEJADOR DE ERRORES EN FORMATO JSON
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/json";

        var exceptionHandlerPathFeature = context.Features.Get<IExceptionHandlerPathFeature>();
        var exception = exceptionHandlerPathFeature?.Error;

        // Ocultamos el código fuente en producción por seguridad (A05 OWASP)
        var errorResponse = new
        {
            error = "Ocurrió un error interno en el servidor. El equipo técnico ya fue notificado.",
            detalle = app.Environment.IsDevelopment() ? exception?.Message : "Información clasificada."
        };

        await context.Response.WriteAsJsonAsync(errorResponse);
    });
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors("AllowAngular");
// 🛡️ 2. ACTIVAR EL MIDDLEWARE (Debe ir ANTES de UseAuthentication y MapControllers)
app.UseRateLimiter();

// 🛡️ ACTIVAR EL MIDDLEWARE GLOBAL DE AUDITORÍA
app.UseMiddleware<SeguridadApiProfesional.Middlewares.SecurityLoggingMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();

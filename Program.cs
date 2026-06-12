using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using VexTrainer.Data.Services;
using VexTrainerAPI.Middleware;
using VexTrainerAPI.Services;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

// =============================================================================
// VexTrainer API — Application Entry Point and Composition Root
//
// This file is the single place where the entire application is wired together.
// It is responsible for three things:
//
//   1. Reading configuration from appsettings.json / environment variables.
//   2. Registering every service with the ASP.NET Core DI container, including
//      lifetime decisions (singleton vs. scoped).
//   3. Assembling the middleware pipeline that every HTTP request passes through
//      before reaching a controller action.
//
// Service lifetimes used here:
//   Singleton  — created once for the process lifetime; safe for stateless,
//                thread-safe services (PasswordService, TokenService/ITokenService).
//   Scoped     — created once per HTTP request; used for services that hold a
//                database connection (AuthService, LessonService, QuizService,
//                AdminService) and for services that touch per-request state
//                (EmailService, ConfirmationTokenService).
//
// Middleware pipeline order (order is significant in ASP.NET Core):
//   HTTPS redirect => CORS => optional request logging =>
//   Authentication => Authorization => Controllers
//
// JWT configuration is validated at startup — a missing secret throws
// immediately rather than failing silently at the first authenticated request.
// =============================================================================

var builder = WebApplication.CreateBuilder(args);

// ===== Kestrel: suppress Server header =====
// IIS outbound rule in web.config handles the IIS layer.
// This suppresses the Kestrel-added Server header at the ASP.NET Core layer.
builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

// Configuration
// All required values are read up front and fail-fast if missing.
// Optional values fall back to safe defaults.

var configuration = builder.Configuration;
var jwtSecret = configuration["Jwt:Secret"] ?? throw new InvalidOperationException("JWT Secret not configured");
var jwtIssuer = configuration["Jwt:Issuer"] ?? "VexTrainerAPI";
var jwtAudience = configuration["Jwt:Audience"] ?? "VexTrainerClients";
var accessTokenExpiryMinutes = int.Parse(configuration["Jwt:AccessTokenExpiryMinutes"] ?? "360");
var refreshTokenExpiryDays = int.Parse(configuration["Jwt:RefreshTokenExpiryDays"] ?? "7");
var connectionString = configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string not configured");

// Service Registration

builder.Services.AddControllers();

// EmailService: scoped because IConfiguration and ILogger are per-request safe;
// sending email is inherently side-effectful and should not be shared across requests.
builder.Services.AddScoped<EmailService>();

// ConfirmationTokenService: scoped because its AES key is derived from the
// connection string at construction time — safe to scope per request.
builder.Services.AddScoped<ConfirmationTokenService>();

// PasswordService: singleton — purely stateless BCrypt operations, no DB access,
// no request state. Safe and efficient to share across all requests.
builder.Services.AddSingleton<PasswordService>();

// ITokenService / TokenService: singleton — stateless JWT generation using
// configuration values read once at startup. Registered via factory so the
// concrete TokenService can receive primitive constructor arguments (strings, ints)
// that the DI container cannot resolve automatically.
builder.Services.AddSingleton<ITokenService>(sp => new TokenService(
    jwtSecret,
    jwtIssuer,
    jwtAudience,
    accessTokenExpiryMinutes,
    refreshTokenExpiryDays
));

// Database-layer services: scoped — each opens a SqlConnection per request
// via Dapper and must not be shared across concurrent requests.
// Registered via factory to pass the connection string as a primitive argument.
builder.Services.AddScoped(sp => new AuthService(
    connectionString,
    sp.GetRequiredService<PasswordService>(),
    sp.GetRequiredService<ITokenService>()
));
builder.Services.AddScoped(sp => new LessonService(connectionString));
builder.Services.AddScoped(sp => new QuizService(connectionString));
builder.Services.AddScoped(sp => new AdminService(connectionString));

// CORS
// Allows the VexTrainer web front-end and local development servers to call the
// API from a browser. AllowCredentials() is required for cookie-based flows
// (e.g., the web Razor Pages app). Mobile apps bypass CORS entirely because they
// do not run in a browser.
builder.Services.AddCors(options => {
  options.AddPolicy("AllowVexTrainer", policy =>
  {
    policy.WithOrigins(
            "https://vextrainer.com",
            "https://www.vextrainer.com",
            "http://localhost:3000",
            "http://localhost:8080",
            "http://localhost:5000",
            "http://localhost:5001"
        )
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials();
  });
});

// JWT Authentication
// Every request bearing an Authorization: Bearer <token> header is validated
// here before reaching any [Authorize] controller action. Key validation points:
//   - Issuer and audience must match the configured values exactly.
//   - Token lifetime is enforced with zero clock skew — expired tokens are
//     rejected immediately with no grace period.
//   - HTTPS is required in production but relaxed in development to allow
//     http://localhost testing without a certificate.
var key = Encoding.ASCII.GetBytes(jwtSecret);
builder.Services.AddAuthentication(options => {
  options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
  options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options => {
  options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
  options.SaveToken = true;
  options.TokenValidationParameters = new TokenValidationParameters {
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = true,
    ValidIssuer = jwtIssuer,
    ValidateAudience = true,
    ValidAudience = jwtAudience,
    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero   // no grace period on expiry
  };
});

builder.Services.AddAuthorization();

// Swagger
// Swagger UI is served at the root path (RoutePrefix = "") so navigating to
// the API root in a browser opens the interactive docs immediately.
// The Bearer security definition allows testing protected endpoints directly
// from the Swagger UI without a separate tool.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => {
  options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo {
    Title = "VexTrainer API",
    Version = "v1",
    Description = "Quiz platform API for VEX PROS programming education"
  });

  options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme {
    Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token.",
    Name = "Authorization",
    In = Microsoft.OpenApi.Models.ParameterLocation.Header,
    Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
    Scheme = "Bearer"
  });

  options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id   = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ===== Rate limiting =====
// API clients (mobile apps) make more requests per session than browser users.
// 300/min per IP covers normal app use; bots and scanners are throttled.
// Auth endpoints get a tighter limit to block credential stuffing.
builder.Services.AddRateLimiter(options =>
{
    // Global: 300 requests per minute per IP
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit          = 300,
                Window               = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit           = 0
            }));

    // Auth endpoints: 10 attempts per 10 minutes per IP (blocks credential stuffing)
    options.AddFixedWindowLimiter("auth", o =>
    {
        o.PermitLimit          = 10;
        o.Window               = TimeSpan.FromMinutes(10);
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit           = 0;
    });

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// Build
var app = builder.Build();

// Middleware Pipeline
// Order matters: each middleware wraps everything that follows it.

if (app.Environment.IsDevelopment()) {
  // Swagger UI at root in development; developer exception page for full stack traces.
  app.UseSwagger();
  app.UseSwaggerUI(options =>
  {
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "VexTrainer API v1");
    options.RoutePrefix = string.Empty;
  });
  app.UseDeveloperExceptionPage();
}
else {
  // Production: exception handler logs the error, fires an email notification,
  // and returns a generic JSON response — no stack trace leakage.
  app.UseExceptionHandler(errorApp =>
  {
      errorApp.Run(async context =>
      {
          var feature = context.Features
              .Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>();

          if (feature?.Error is not null)
          {
              app.Logger.LogError(feature.Error, "Unhandled API exception");

              // Fire-and-forget — email must not delay the error response
              _ = Task.Run(async () =>
              {
                  try
                  {
                      await ErrorNotification.SendAsync(
                          feature.Error, context, app.Configuration, "VexTrainer API");
                  }
                  catch (Exception emailEx)
                  {
                      app.Logger.LogError(emailEx, "Error notification email failed");
                  }
              });
          }

          // Return the same ApiResponse envelope the clients expect
          context.Response.StatusCode  = 500;
          context.Response.ContentType = "application/json";
          await context.Response.WriteAsJsonAsync(new
          {
              success    = false,
              message    = "An unexpected error occurred",
              resultCode = 99
          });
      });
  });
  app.UseHsts();
}

// ===== Security headers middleware =====
// Belt-and-suspenders with web.config — covers edge cases where the IIS
// layer is bypassed (e.g. direct Kestrel access during local testing).
app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        var h = context.Response.Headers;
        h.Remove("Server");
        h.Remove("X-Powered-By");
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"]        = "DENY";
        h["Referrer-Policy"]        = "strict-origin-when-cross-origin";
        return Task.CompletedTask;
    });
    await next();
});

app.UseHttpsRedirection();
app.UseCors("AllowVexTrainer");

// Optional request/response logging — enabled in development automatically
// or explicitly via EnableRequestLogging config flag in any environment.
// Logs full request and response bodies; never enable in production without
// confirming no PII (passwords, tokens) can appear in request bodies.
if (app.Environment.IsDevelopment() || app.Configuration.GetValue<bool>("EnableRequestLogging")) {
  app.UseRequestResponseLogging();
  app.Logger.LogWarning("*** Request/Response logging is ENABLED ***");
}

app.UseRateLimiter();

// Authentication must precede Authorization — auth populates the ClaimsPrincipal
// that authorization policies and [Authorize] attributes inspect.
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Infrastructure Endpoints

// /health — used by load balancers and uptime monitors to confirm the process
// is running. Returns a lightweight JSON response with no DB round trip.
app.MapGet("/health", () => Results.Ok(new {
  status = "healthy",
  timestamp = DateTime.UtcNow,
  version = "1.0.0"
}));

// /error — catch-all for unhandled exceptions in production; returns a generic
// RFC 7807 Problem Details response without exposing internals.
app.MapGet("/error", () => Results.Problem("An error occurred"));

app.Logger.LogInformation("VexTrainer API starting...");
app.Run();

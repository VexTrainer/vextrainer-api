# VexTrainer API

This repository is part of the [VexTrainer](https://vextrainer.com) platform,
a free, community-driven learning platform that teaches VEX Robotics Competition
(VRC) programming to students and teams worldwide.

VexTrainer provides structured lessons and quizzes covering the VEX PROS C++
programming environment, from hardware basics and motor control through to
autonomous driving and PID control. Lessons are readable on the web, and both
lessons and quizzes are available on Android and iOS mobile apps.

The platform is free to use. If you find it helpful, donations are welcome to
support farmers in need. Community contributions to the curriculum are also
welcome. See [vextrainer-content](https://github.com/VexTrainer/vextrainer-content)
for details.

---

## About This Repository

`vextrainer-api` is the **REST API backend** for the VexTrainer platform.
It is an ASP.NET Core 8 Web API hosted on Windows IIS, serving both the
.NET website and the Android and iOS mobile apps from a single endpoint.

It handles:
- **Authentication** - registration, login, logout, JWT token refresh, email confirmation
- **Password management** - forgot password, reset password flows
- **Account management** - profile access, account deletion workflow
- **Lessons and modules** - curriculum content delivery
- **Quizzes** - quiz retrieval, attempt tracking, answer submission and scoring
- **User progress** - lesson read tracking, topic read tracking, quiz history

All data access goes through stored procedures in SQL Server via the shared
[vextrainer-data](https://github.com/VexTrainer/vextrainer-data) library.
No direct table access. All permissions are enforced at the database level.

---

## Platform Repositories

The VexTrainer platform is made up of five repositories:

| Repository | Description |
|---|---|
| [vextrainer-api](https://github.com/VexTrainer/vextrainer-api) | You are here - REST API backend |
| [vextrainer-data](https://github.com/VexTrainer/vextrainer-data) | Shared data access layer |
| [vextrainer-web](https://github.com/VexTrainer/vextrainer-web) | .NET website for reading lessons |
| [vextrainer-android](https://github.com/VexTrainer/vextrainer-android) | Android app for lessons and quizzes |
| [vextrainer-ios](https://github.com/VexTrainer/vextrainer-ios) | iOS app for lessons and quizzes |
| [vextrainer-content](https://github.com/VexTrainer/vextrainer-content) | Free VEX programming curriculum |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | ASP.NET Core 8 Web API |
| Language | C# / .NET 8 |
| Database | SQL Server 2022 (via vextrainer-data) |
| Data access | Dapper (via vextrainer-data) |
| Authentication | JWT Bearer - `Microsoft.AspNetCore.Authentication.JwtBearer` |
| Token handling | `System.IdentityModel.Tokens.Jwt` |
| Password hashing | BCrypt (via vextrainer-data) |
| API documentation | Swagger / OpenAPI - `Swashbuckle.AspNetCore` |
| Hosting | Windows IIS (shared hosting) |

---

## Repository Structure

```
vextrainer-api/
|-- Controllers/         # API endpoint controllers
|-- Middleware/          # Custom middleware (request/response logging)
|-- Models/              # API-layer request and response models
|-- Services/            # Application services (email, tokens, confirmation)
|-- Program.cs           # Application entry point, DI registration, middleware pipeline
|-- appsettings.json     # Configuration template (no real credentials)
|-- web.config           # IIS hosting configuration
|-- VexTrainerAPI.csproj # Project file and NuGet dependencies
```

---

## API Documentation

Swagger UI is available in local development only and is not exposed
in production. When running locally it is served at the root:

```
https://localhost:5001
```

Authenticated endpoints require a Bearer token. Use the `/auth/login`
endpoint to obtain a token, then click **Authorize** in Swagger UI and
enter `Bearer <your-token>`.

---

## Getting Started

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8)
- SQL Server 2022 (or SQL Server Express)
- Visual Studio 2022 or VS Code

### 1 - Clone the required repositories

This API depends on the shared data layer. Clone both:

```bash
git clone https://github.com/VexTrainer/vextrainer-api.git
git clone https://github.com/VexTrainer/vextrainer-data.git
```

Both must be cloned into sibling folders:
```
parent-folder/
|-- VexTrainer/         <- vextrainer-api
|--VexTrainer.Data/     <- vextrainer-data
```

### 2 - Set up the database

Follow the database setup instructions in
[vextrainer-data/sql/README.md](https://github.com/VexTrainer/vextrainer-data/blob/main/sql/README.md).

This covers creating the database, logins, tables, and stored procedures.

### 3 - Configure the application

Copy `appsettings.json` as a starting point and create
`appsettings.Development.json` with your local values:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=VexTrainer01;User Id=vextrainer_teachers;Password=your-password;"
  },
  "Email": {
    "SmtpServer": "your-smtp-server",
    "SmtpPort": 25,
    "EnableSsl": false,
    "FromEmail": "noreply@yourdomain.com",
    "FromPassword": "your-email-password",
    "FromName": "VexTraining Platform",
    "FeedbackRecipient": "feedback@yourdomain.com"
  },
  "Jwt": {
    "Secret": "your-secret-key-minimum-32-characters",
    "Issuer": "VexTrainerAPI",
    "Audience": "VexTrainerClients",
    "AccessTokenExpiryMinutes": 30,
    "RefreshTokenExpiryDays": 7
  }
}
```

### IMPORTANT:
> `appsettings.Development.json` is excluded from git via `.gitignore`.
> Never commit real credentials to this repository.

> The JWT secret must be at least 32 characters long. Use a randomly
> generated string. Do not use a dictionary word or phrase.

### 4 - Restore and run

```bash
cd VexTrainer
dotnet restore
dotnet run
```

Navigate to `https://localhost:5001` and Swagger UI opens automatically.

---

## Security Model

| Concern | Approach |
|---|---|
| Authentication | JWT Bearer tokens with configurable expiry |
| Token refresh | Refresh token rotation - old tokens invalidated on refresh |
| Password storage | BCrypt hashing - plain text passwords never stored |
| Database access | Stored procedures only - no direct table permissions |
| CORS | Restricted to `vextrainer.com` and localhost in development |
| HTTPS | Required in production, relaxed for localhost development |
| Token expiry | Zero clock skew - expired tokens rejected immediately |
| Swagger UI | Development environment only - not exposed in production |
| Request logging | Disabled by default - never enable in production with PII in request bodies |

---

## Contributing

For code contributions, please open an issue first to discuss the
change before submitting a pull request.

For curriculum content contributions, see
[vextrainer-content](https://github.com/VexTrainer/vextrainer-content).

---

## License

Code in this repository is licensed under the [MIT License](LICENSE).

Curriculum content in
[vextrainer-content](https://github.com/VexTrainer/vextrainer-content)
is licensed under
[Creative Commons Attribution-NonCommercial 4.0](https://creativecommons.org/licenses/by-nc/4.0/).
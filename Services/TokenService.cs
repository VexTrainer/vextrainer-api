using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using VexTrainer.Data.Services;

namespace VexTrainerAPI.Services;

/// <summary>
/// Concrete implementation of ITokenService. Generates JWT access tokens and
/// opaque refresh tokens for use in the VexTrainer authentication flow.
///
/// Registered as a singleton in Program.cs because all state is read-only
/// configuration captured at construction time — the service is fully
/// thread-safe and carries no per-request data.
///
/// JWT claims embedded in every access token:
///   NameIdentifier (sub) — the user's numeric database ID
///   Name                 — the user's display name
///   Role                 — the user's role (e.g., "User", "Admin")
///   Email                — optional; included when available so controllers
///                          can read the email from HttpContext without a DB lookup
///
/// Token lifetimes are driven by appsettings.json:
///   Jwt:AccessTokenExpiryMinutes  — default 360 (6 hours)
///   Jwt:RefreshTokenExpiryDays    — default 7
/// </summary>
public class TokenService : ITokenService {
  private readonly string _secret;
  private readonly string _issuer;
  private readonly string _audience;
  private readonly int _accessTokenExpiryMinutes;
  private readonly int _refreshTokenExpiryDays;

  public TokenService(
      string secret,
      string issuer,
      string audience,
      int accessTokenExpiryMinutes,
      int refreshTokenExpiryDays) {
    _secret = secret;
    _issuer = issuer;
    _audience = audience;
    _accessTokenExpiryMinutes = accessTokenExpiryMinutes;
    _refreshTokenExpiryDays = refreshTokenExpiryDays;
  }

  /// <summary>
  /// Generates a signed HS256 JWT access token containing the user's identity
  /// and role as claims.
  ///
  /// The email claim is conditional — it is only added when a non-empty value
  /// is supplied. This keeps the token lean during flows where email is not
  /// available (e.g., token refresh) while allowing it to be embedded during
  /// registration and login so that ContactController and other controllers
  /// can read it from the JWT without a database round trip.
  ///
  /// The expiry date is returned alongside the token so the client can store
  /// it and proactively request a refresh before the token expires, avoiding
  /// a failed API call mid-session.
  /// </summary>
  public (string token, DateTime expiryDate) GenerateAccessToken(
      int userId,
      string userName,
      string roleName,
      string email = "") {
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(_secret);
    var expiryDate = DateTime.UtcNow.AddMinutes(_accessTokenExpiryMinutes);

    var claims = new List<Claim>
    {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name,           userName),
            new Claim(ClaimTypes.Role,           roleName)
        };

    // Embed email so controllers can read it without a DB lookup
    if (!string.IsNullOrWhiteSpace(email))
      claims.Add(new Claim(ClaimTypes.Email, email));

    var tokenDescriptor = new SecurityTokenDescriptor {
      Subject = new ClaimsIdentity(claims),
      Expires = expiryDate,
      Issuer = _issuer,
      Audience = _audience,
      SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return (tokenHandler.WriteToken(token), expiryDate);
  }

  /// <summary>
  /// Generates a cryptographically random 64-byte refresh token encoded as
  /// Base64. The token is opaque — it carries no user information and is only
  /// meaningful when looked up in the session table.
  ///
  /// Note: the raw Base64 output may contain '+', '/' and '=' characters.
  /// If this token is ever placed in a URL (e.g., a query parameter) it must
  /// be URL-encoded by the caller. When stored in the Authorization header
  /// or a JSON body, it is safe as-is.
  /// </summary>
  public string GenerateRefreshToken() {
    var randomBytes = new byte[64];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(randomBytes);
    return Convert.ToBase64String(randomBytes);
  }

  /// <summary>
  /// Returns the UTC timestamp at which a newly issued refresh token will expire.
  /// Convenience method for callers that need to store or display the expiry
  /// without generating an actual token.
  /// </summary>
  public DateTime GetRefreshTokenExpiryDate() => DateTime.UtcNow.AddDays(_refreshTokenExpiryDays);

  /// <summary>
  /// Returns the UTC timestamp at which a newly issued access token will expire.
  /// Mirrors GetRefreshTokenExpiryDate for the shorter-lived access token window.
  /// </summary>
  public DateTime GetAccessTokenExpiryDate() => DateTime.UtcNow.AddMinutes(_accessTokenExpiryMinutes);
}

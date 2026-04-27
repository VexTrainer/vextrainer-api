// UserController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using VexTrainerAPI.Services;
using VexTrainer.Data.Services;
using VexTrainer.Data.Models;

namespace VexTrainerAPI.Controllers;

/// <summary>
/// Serves the student's personal dashboard and quiz history. Intentionally
/// thin — both actions are single-call delegations to QuizService. The
/// controller exists as a separate class (rather than adding these to
/// QuizController) because these endpoints represent the user's own data
/// view, not quiz mechanics.
///
/// Endpoint summary:
///   GET /User/dashboard          — aggregate stats + recent attempts
///   GET /User/history            — paginated history of all past attempts
/// </summary>
[Authorize]
[ApiController]
[Route("[controller]")]
public class UserController : ControllerBase {
  private readonly QuizService _quizService;
  private readonly ILogger<UserController> _logger;

  public UserController(QuizService quizService, ILogger<UserController> logger) {
    _quizService = quizService;
    _logger = logger;
  }

  /// <summary>
  /// Returns the student's home dashboard: aggregate stats (total attempts,
  /// overall pass rate, average score) and a list of their most recent quiz
  /// attempts. Returns an empty UserDashboard object for brand-new users.
  ///
  /// GET /User/dashboard
  /// </summary>
  [HttpGet("dashboard")]
  public async Task<IActionResult> GetDashboard() {
    var result = await _quizService.GetUserDashboardAsync(GetUserId());
    return Ok(result);
  }

  /// <summary>
  /// Returns a paginated list of all quiz attempts the user has ever made,
  /// most recent first. The query parameter is named "limit" (common REST
  /// convention) and passed through to QuizService as "pageSize". Total
  /// record count is included in the response for client-side page calculation.
  ///
  /// GET /User/history?page=1&amp;limit=20
  /// </summary>
  [HttpGet("history")]
  public async Task<IActionResult> GetHistory([FromQuery] int page = 1, [FromQuery] int limit = 20) {
    var result = await _quizService.GetUserQuizHistoryAsync(GetUserId(), page, limit);
    return Ok(result);
  }

  private int GetUserId() {
    var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    return int.Parse(userIdClaim ?? "0");
  }
}

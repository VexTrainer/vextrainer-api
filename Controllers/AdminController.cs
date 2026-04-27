// AdminController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VexTrainerAPI.Services;
using VexTrainer.Data.Services;
using VexTrainer.Data.Models;
namespace VexTrainerAPI.Controllers;

/// <summary>
/// Provides platform-wide administrative reporting and user management.
/// Every endpoint in this controller is gated by [Authorize(Roles = "Admin")]
/// at the class level, which means the JWT middleware rejects any token that
/// does not carry a Role claim of "Admin" before the action method is reached.
///
/// Validation note: input validation is minimal in this controller — see the
/// "Why controllers don't validate" section in the shared note at the end of
/// this file.
///
/// Endpoint summary:
///   GET    /Admin/dashboard                     — platform-wide stats and activity
///   GET    /Admin/quizzes/{quizId}/statistics   — per-quiz performance drill-down
///   GET    /Admin/users                         — paginated user list
///   PUT    /Admin/users/{userId}/role           — change a user's role
///   DELETE /Admin/users/{userId}                — soft-deactivate a user
///   GET    /Admin/categories/performance        — category-level pass-rate report
/// </summary>
[Authorize(Roles = "Admin")]
[ApiController]
[Route("[controller]")]
public class AdminController : ControllerBase {
  private readonly AdminService _adminService;
  private readonly ILogger<AdminController> _logger;

  public AdminController(AdminService adminService, ILogger<AdminController> logger) {
    _adminService = adminService;
    _logger = logger;
  }

  /// <summary>
  /// Returns the admin home dashboard: platform-wide aggregate stats, the most
  /// popular quizzes, recently registered users, and active users in the past
  /// 30 days. All data is assembled by sp_GetAdminDashboard in a single query.
  ///
  /// GET /Admin/dashboard
  /// </summary>
  [HttpGet("dashboard")]
  public async Task<IActionResult> GetDashboard() {
    var result = await _adminService.GetAdminDashboardAsync();
    return Ok(result);
  }

  /// <summary>
  /// Returns detailed statistics for a specific quiz: attempt count, pass rate,
  /// average score, and a per-question difficulty breakdown showing which
  /// questions students are most frequently getting wrong.
  ///
  /// GET /Admin/quizzes/{quizId}/statistics
  /// </summary>
  [HttpGet("quizzes/{quizId}/statistics")]
  public async Task<IActionResult> GetQuizStatistics(short quizId) {
    var result = await _adminService.GetQuizStatisticsAsync(quizId);
    return Ok(result);
  }

  /// <summary>
  /// Returns a paginated list of all registered users with their role and
  /// account status. The query parameter is named "limit" here (matching
  /// common REST conventions) but is passed as "pageSize" to AdminService
  /// which names it consistently with the other paginated methods.
  ///
  /// GET /Admin/users?page=1&amp;limit=50
  /// </summary>
  [HttpGet("users")]
  public async Task<IActionResult> GetAllUsers([FromQuery] int page = 1, [FromQuery] int limit = 50) {
    var result = await _adminService.GetAllUsersAsync(page, limit);
    return Ok(result);
  }

  /// <summary>
  /// Changes the role assigned to a user account (e.g., promoting to Admin or
  /// demoting back to Student). Returns 400 if the stored procedure rejects the
  /// change (e.g., invalid role ID or target user not found).
  ///
  /// Note: the controller does not prevent an admin from changing their own role.
  /// That guard should be added here or in sp_UpdateUserRole if required.
  ///
  /// PUT /Admin/users/{userId}/role
  /// </summary>
  [HttpPut("users/{userId}/role")]
  public async Task<IActionResult> UpdateUserRole(int userId, [FromBody] UpdateUserRoleRequest request) {
    var result = await _adminService.UpdateUserRoleAsync(userId, request.RoleId);

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Soft-deactivates a user account, preventing login without deleting data.
  /// Uses HTTP DELETE because the operation removes the user's ability to access
  /// the platform, even though the database row is preserved. Returns 400 if
  /// the target user is not found or is already inactive.
  ///
  /// DELETE /Admin/users/{userId}
  /// </summary>
  [HttpDelete("users/{userId}")]
  public async Task<IActionResult> DeactivateUser(int userId) {
    var result = await _adminService.DeactivateUserAsync(userId);

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Returns aggregate pass rates, average scores, and attempt counts grouped
  /// by quiz category across all users. Used to identify curriculum areas where
  /// students are consistently struggling.
  ///
  /// GET /Admin/categories/performance
  /// </summary>
  [HttpGet("categories/performance")]
  public async Task<IActionResult> GetCategoryPerformance() {
    var result = await _adminService.GetCategoryPerformanceAsync();
    return Ok(result);
  }
}

// LessonController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using VexTrainerAPI.Services;
using VexTrainer.Data.Services;
using VexTrainer.Data.Models;

namespace VexTrainerAPI.Controllers;

/// <summary>
/// Serves the VexTrainer curriculum — modules, lessons, topics — and records
/// reading progress. All endpoints require authentication; the user's ID is
/// read from the JWT so the database layer can join against their progress data
/// in a single round trip.
///
/// The curriculum hierarchy exposed by this controller is:
///   Module → Lesson → Topic
///
/// Endpoint summary:
///   GET  /Lesson/modules                            — all modules with progress
///   GET  /Lesson/modules/{moduleId}/lessons         — lessons in a module
///   GET  /Lesson/lessons                            — all lessons (flat, for search)
///   GET  /Lesson/lessons/{lessonId}                 — single lesson detail
///   GET  /Lesson/lessons/{lessonId}/topics          — topics in a lesson (ordered)
///   GET  /Lesson/topics/{topicId}/details           — topic content + nav + breadcrumb
///   POST /Lesson/lessons/{lessonId}/mark-read       — record lesson as read
///   POST /Lesson/topics/{topicId}/mark-read         — record topic as read
///   GET  /Lesson/progress                           — user reading dashboard
///   GET  /Lesson/app-dashboard                      — mobile app home dashboard
///   GET    /Lesson/bookmarks                          — user's bookmarks
///   POST   /Lesson/topics/{topicId}/bookmark          — add bookmark
///   DELETE /Lesson/topics/{topicId}/bookmark          — remove bookmark
/// </summary>
[Authorize]
[ApiController]
[Route("[controller]")]
public class LessonController : ControllerBase {
  private readonly LessonService _lessonService;
  private readonly ILogger<LessonController> _logger;

  public LessonController(LessonService lessonService, ILogger<LessonController> logger) {
    _lessonService = lessonService;
    _logger = logger;
  }

  /// <summary>
  /// Returns all curriculum modules, each decorated with the user's completion
  /// status so the home screen can show progress indicators without a second call.
  ///
  /// GET /Lesson/modules
  /// </summary>
  [HttpGet("modules")]
  public async Task<IActionResult> GetModules() {
    var result = await _lessonService.GetModulesAsync(GetUserId());
    return Ok(result);
  }

  /// <summary>
  /// Returns all lessons within a module, each with the user's read status.
  ///
  /// GET /Lesson/modules/{moduleId}/lessons
  /// </summary>
  [HttpGet("modules/{moduleId}/lessons")]
  public async Task<IActionResult> GetLessonsByModule(short moduleId) {
    var result = await _lessonService.GetLessonsByModuleAsync(moduleId, GetUserId());
    return Ok(result);
  }

  /// <summary>
  /// Returns the detail record for a single lesson. Returns 404 if the lesson
  /// ID does not exist in the database (sp_GetLessonDetails sets result_code != 0).
  ///
  /// GET /Lesson/lessons/{lessonId}
  /// </summary>
  [HttpGet("lessons/{lessonId}")]
  public async Task<IActionResult> GetLessonDetails(short lessonId) {
    var result = await _lessonService.GetLessonDetailsAsync(lessonId, GetUserId());

    if (!result.Success)
      return NotFound(result);

    return Ok(result);
  }

  /// <summary>
  /// Returns all topics within a lesson in display_order sequence. The ordering
  /// is guaranteed by the stored procedure — the client must not re-sort the list
  /// or the reading sequence will break.
  ///
  /// GET /Lesson/lessons/{lessonId}/topics
  /// </summary>
  [HttpGet("lessons/{lessonId}/topics")]
  public async Task<IActionResult> GetTopicsByLesson(short lessonId) {
    var result = await _lessonService.GetTopicsByLessonAsync(lessonId, GetUserId());
    return Ok(result);
  }

  /// <summary>
  /// Returns the full content metadata and navigation context for a single topic,
  /// including the prev/next topic IDs for forward/back navigation and the full
  /// Module → Lesson → Topic breadcrumb trail. Returns 404 if not found.
  ///
  /// GET /Lesson/topics/{topicId}/details
  /// </summary>
  [HttpGet("topics/{topicId}/details")]
  [ProducesResponseType(typeof(ApiResponse<TopicDetails>), 200)]
  public async Task<IActionResult> GetTopicDetails(int topicId) {
    var result = await _lessonService.GetTopicDetailsAsync(topicId, GetUserId());

    if (!result.Success)
      return NotFound(result);

    return Ok(result);
  }

  /// <summary>
  /// Records that the authenticated user has read the specified lesson.
  /// The stored procedure upserts the progress row — safe to call multiple
  /// times (e.g., if the user revisits the lesson).
  ///
  /// POST /Lesson/lessons/{lessonId}/mark-read
  /// </summary>
  [HttpPost("lessons/{lessonId}/mark-read")]
  public async Task<IActionResult> MarkLessonRead(short lessonId) {
    var result = await _lessonService.MarkLessonReadAsync(lessonId, GetUserId());

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Records that the authenticated user has read the specified topic.
  /// Mirrors MarkLessonRead at the finer topic level. Safe to call on revisit.
  ///
  /// POST /Lesson/topics/{topicId}/mark-read
  /// </summary>
  [HttpPost("topics/{topicId}/mark-read")]
  public async Task<IActionResult> MarkTopicRead(int topicId) {
    var result = await _lessonService.MarkTopicReadAsync(topicId, GetUserId());

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Returns the user's reading progress dashboard: overall completion stats,
  /// recent lessons, and per-module progress breakdown. Returns an empty
  /// ReadingProgress object (not null) for brand-new users with no activity.
  ///
  /// GET /Lesson/progress
  /// </summary>
  [HttpGet("progress")]
  public async Task<IActionResult> GetReadingProgress() {
    var result = await _lessonService.GetReadingProgressAsync(GetUserId());
    return Ok(result);
  }

  /// <summary>
  /// Returns the authenticated user's bookmarks, each carrying its full
  /// Module → Lesson → Topic context so the client can render the list
  /// without follow-up lookups. Ordered in curriculum sequence by the
  /// stored procedure — the client must not re-sort.
  ///
  /// GET /Lesson/bookmarks
  /// </summary>
  [HttpGet("bookmarks")]
  [ProducesResponseType(typeof(ApiResponse<List<Bookmark>>), 200)]
  public async Task<IActionResult> GetBookmarks() {
    var result = await _lessonService.GetBookmarksAsync(GetUserId());
    return Ok(result);
  }

  /// <summary>
  /// Bookmarks a topic for the authenticated user. Idempotent — calling
  /// this on a topic that is already bookmarked is a silent no-op that
  /// still returns 200, so the client can treat the bookmark button as
  /// a simple toggle without first checking server state.
  ///
  /// POST /Lesson/topics/{topicId}/bookmark
  /// </summary>
  [HttpPost("topics/{topicId}/bookmark")]
  public async Task<IActionResult> AddBookmark(int topicId) {
    var result = await _lessonService.AddBookmarkAsync(GetUserId(), topicId);

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Removes a topic bookmark for the authenticated user. Idempotent —
  /// deleting a bookmark that does not exist still returns 200, so the
  /// client can treat the bookmark button as a simple toggle.
  ///
  /// DELETE /Lesson/topics/{topicId}/bookmark
  /// </summary>
  [HttpDelete("topics/{topicId}/bookmark")]
  public async Task<IActionResult> DeleteBookmark(int topicId) {
    var result = await _lessonService.DeleteBookmarkAsync(GetUserId(), topicId);

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Returns the mobile-app home dashboard for the authenticated user:
  /// overall stats (with reading streak), the continue-learning list, and
  /// the user's bookmarks. A trimmed counterpart to the web dashboard —
  /// backed by sp_GetUserAppDashboard, which emits the first three result
  /// sets. Always returns a valid payload (empty stats / empty lists) for
  /// brand-new users with no activity, so the app can bind without null
  /// checks.
  ///
  /// GET /Lesson/app-dashboard
  /// </summary>
  [HttpGet("app-dashboard")]
  [ProducesResponseType(typeof(ApiResponse<UserAppDashboard>), 200)]
  public async Task<IActionResult> GetAppDashboard() {
    var result = await _lessonService.GetUserAppDashboardAsync(GetUserId());
    return Ok(result);
  }

  /// <summary>
  /// Returns all lessons across all modules in a flat list, each with the user's
  /// read status. Intended for search results or admin-style browse views where
  /// the Module → Lesson hierarchy is not needed.
  ///
  /// GET /Lesson/lessons
  /// </summary>
  [HttpGet("lessons")]
  public async Task<IActionResult> GetAllLessons() {
    var result = await _lessonService.GetAllLessonsAsync(GetUserId());
    return Ok(result);
  }

  private int GetUserId() {
    var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    return int.Parse(userIdClaim ?? "0");
  }
}
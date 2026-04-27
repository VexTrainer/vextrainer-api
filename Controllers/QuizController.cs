// QuizController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using VexTrainerAPI.Services;
using VexTrainer.Data.Services;
using VexTrainer.Data.Models;

namespace VexTrainerAPI.Controllers;

/// <summary>
/// Drives the full quiz-taking lifecycle from browsing categories to reviewing
/// results. All endpoints require authentication.
///
/// A complete quiz session flows through these endpoints in order:
///   1. GET  /Quiz/categories                            — browse the category tree
///   2. GET  /Quiz/categories/{id}/quizzes               — list quizzes in a category
///   3. GET  /Quiz/quizzes/{quizId}                      — view quiz details before starting
///   4. POST /Quiz/quizzes/{quizId}/start                — create attempt; receive attemptId
///   5. GET  /Quiz/attempts/{attemptId}/questions        — fetch randomised question set
///   6. POST /Quiz/attempts/{attemptId}/answer  (×N)    — submit one answer at a time
///   7. POST /Quiz/attempts/{attemptId}/complete         — close attempt; receive final score
///   8. GET  /Quiz/attempts/{attemptId}/results          — full per-question breakdown
///
/// An interrupted session can be recovered via:
///   GET /Quiz/attempts/{attemptId}/resume               — restore attempt state + answered IDs
/// </summary>
[Authorize]
[ApiController]
[Route("[controller]")]
public class QuizController : ControllerBase {
  private readonly QuizService _quizService;
  private readonly ILogger<QuizController> _logger;

  public QuizController(QuizService quizService, ILogger<QuizController> logger) {
    _quizService = quizService;
    _logger = logger;
  }

  /// <summary>
  /// Returns the full category tree with parent-child relationships assembled
  /// in memory. No user context needed — categories are global.
  ///
  /// GET /Quiz/categories
  /// </summary>
  [HttpGet("categories")]
  public async Task<IActionResult> GetCategories() {
    var result = await _quizService.GetCategoriesAsync();
    return Ok(result);
  }

  /// <summary>
  /// Returns all quizzes in a category, each decorated with the user's best
  /// score and attempt count so the category list can show progress badges.
  ///
  /// GET /Quiz/categories/{categoryId}/quizzes
  /// </summary>
  [HttpGet("categories/{categoryId}/quizzes")]
  public async Task<IActionResult> GetQuizzesByCategory(short categoryId) {
    var result = await _quizService.GetQuizzesByCategoryAsync(categoryId, GetUserId());
    return Ok(result);
  }

  /// <summary>
  /// Returns the metadata for a single quiz (question count, passing threshold,
  /// previous best score) for the pre-start detail screen. Returns 404 if the
  /// quiz ID does not exist.
  ///
  /// GET /Quiz/quizzes/{quizId}
  /// </summary>
  [HttpGet("quizzes/{quizId}")]
  public async Task<IActionResult> GetQuizDetails(short quizId) {
    var result = await _quizService.GetQuizDetailsAsync(quizId, GetUserId());

    if (!result.Success)
      return NotFound(result);

    return Ok(result);
  }

  /// <summary>
  /// Creates a new attempt record in the database and returns the attempt ID
  /// and total question count. The attempt ID must be retained by the client
  /// for all subsequent calls in this quiz session. Returns 400 if the stored
  /// procedure rejects the start (e.g., attempt limit reached).
  ///
  /// POST /Quiz/quizzes/{quizId}/start
  /// </summary>
  [HttpPost("quizzes/{quizId}/start")]
  public async Task<IActionResult> StartQuiz(short quizId) {
    var result = await _quizService.StartQuizAttemptAsync(quizId, GetUserId());

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Returns the randomised question set for an active attempt, with all answer
  /// options assembled onto each question. Questions are randomised by the stored
  /// procedure so the order differs between attempts.
  ///
  /// GET /Quiz/attempts/{attemptId}/questions
  /// </summary>
  [HttpGet("attempts/{attemptId}/questions")]
  public async Task<IActionResult> GetQuizQuestions(int attemptId) {
    var result = await _quizService.GetQuizQuestionsAsync(attemptId, GetUserId());

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Submits one answer and returns immediate feedback: whether it was correct,
  /// the explanation, the correct answer, the running score, and a count of
  /// questions answered so far.
  ///
  /// POST /Quiz/attempts/{attemptId}/answer
  /// </summary>
  [HttpPost("attempts/{attemptId}/answer")]
  public async Task<IActionResult> SubmitAnswer(int attemptId, [FromBody] SubmitAnswerRequest request) {
    var result = await _quizService.SubmitAnswerAsync(attemptId, request, GetUserId());

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Closes the attempt and calculates the final score. After this call the
  /// attempt is marked complete and cannot receive further answer submissions.
  /// Returns the final percentage, correct answer count, and pass/fail flag.
  ///
  /// POST /Quiz/attempts/{attemptId}/complete
  /// </summary>
  [HttpPost("attempts/{attemptId}/complete")]
  public async Task<IActionResult> CompleteQuiz(int attemptId) {
    var result = await _quizService.CompleteQuizAsync(attemptId, GetUserId());

    if (!result.Success)
      return BadRequest(result);

    return Ok(result);
  }

  /// <summary>
  /// Returns the full post-quiz result breakdown: a summary row and a
  /// per-question list showing what the user answered, whether it was correct,
  /// and the explanation. Intended for the review screen after completion.
  /// Returns 404 if the attempt ID is not found or does not belong to this user.
  ///
  /// GET /Quiz/attempts/{attemptId}/results
  /// </summary>
  [HttpGet("attempts/{attemptId}/results")]
  public async Task<IActionResult> GetQuizResults(int attemptId) {
    var result = await _quizService.GetQuizResultsAsync(attemptId, GetUserId());

    if (!result.Success)
      return NotFound(result);

    return Ok(result);
  }

  /// <summary>
  /// Re-enters an in-progress attempt, returning the attempt metadata and the
  /// list of question IDs already answered so the client can skip them and
  /// resume from where the user left off. Returns 404 if the attempt is not
  /// found or is already completed.
  ///
  /// GET /Quiz/attempts/{attemptId}/resume
  /// </summary>
  [HttpGet("attempts/{attemptId}/resume")]
  public async Task<IActionResult> ResumeQuiz(int attemptId) {
    var result = await _quizService.ResumeQuizAttemptAsync(attemptId, GetUserId());

    if (!result.Success)
      return NotFound(result);

    return Ok(result);
  }

  private int GetUserId() {
    var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    return int.Parse(userIdClaim ?? "0");
  }
}
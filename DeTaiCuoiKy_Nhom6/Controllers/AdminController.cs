using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using DeTaiCuoiKy_Nhom6.Data;
using DeTaiCuoiKy_Nhom6.Models;

namespace DeTaiCuoiKy_Nhom6.Controllers
{
    public class AdminController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly IHttpContextAccessor _http;

        public AdminController(ApplicationDbContext db, IHttpContextAccessor http)
        {
            _db = db;
            _http = http;
        }

        // ─── Auth Helpers ───

        private bool IsAdmin => HttpContext.Session.GetString("Role") == "Admin";
        private int? AdminId => HttpContext.Session.GetInt32("UserId");
        private string ClientIp => _http.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        private void Log(string action, string? desc = null)
        {
            _db.ActivityLogs.Add(new ActivityLog
            {
                UserId = AdminId,
                Action = action,
                Description = desc,
                IpAddress = ClientIp,
                CreatedAt = DateTime.Now
            });
            _db.SaveChanges();
        }

        // ─── DASHBOARD ───

        public async Task<IActionResult> Index()
        {
            if (!IsAdmin) return RedirectToAction("Login");

            var allUsers = await _db.Users.Where(u => u.Role == "User").ToListAsync();
            var allTasks = await _db.Tasks.Include(t => t.User).ToListAsync();

            // Stats
            ViewBag.TotalUsers = allUsers.Count;
            ViewBag.LockedUsers = allUsers.Count(u => u.IsLocked);
            ViewBag.TotalTasks = allTasks.Count;
            ViewBag.CompletedTasks = allTasks.Count(t => t.IsCompleted);
            ViewBag.PendingTasks = allTasks.Count(t => !t.IsCompleted);
            ViewBag.OverdueTasks = allTasks.Count(t => t.IsOverdue && !t.IsCompleted);

            // Tasks per user (top 5)
            ViewBag.UserTaskCounts = allUsers
                .Select(u => new { u.Username, Count = allTasks.Count(t => t.UserId == u.Id) })
                .OrderByDescending(x => x.Count)
                .Take(5)
                .ToList();

            // Activity logs (20 gần nhất)
            var logs = await _db.ActivityLogs
                .Include(a => a.User)
                .OrderByDescending(a => a.CreatedAt)
                .Take(20)
                .ToListAsync();

            ViewBag.Users = allUsers;
            ViewBag.Tasks = allTasks.OrderByDescending(t => t.CreatedAt).Take(50).ToList();
            ViewBag.Logs = logs;
            ViewBag.AdminName = HttpContext.Session.GetString("FullName") ?? "Admin";

            return View();
        }

        // ─── LOGIN ───

        [HttpGet]
        public IActionResult Login()
        {
            if (IsAdmin) return RedirectToAction("Index");
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            var clean = (username ?? "").Trim().ToLower();
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username.ToLower() == clean && u.Role == "Admin");

            if (user == null || !BCrypt.Net.BCrypt.Verify((password ?? "").Trim(), user.PasswordHash))
            {
                ViewBag.Error = "Tên đăng nhập hoặc mật khẩu không đúng!";
                return View();
            }

            if (user.IsLocked)
            {
                ViewBag.Error = "Tài khoản Admin đã bị khóa!";
                return View();
            }

            user.LastLoginAt = DateTime.Now;
            await _db.SaveChangesAsync();

            HttpContext.Session.SetInt32("UserId", user.Id);
            HttpContext.Session.SetString("Username", user.Username);
            HttpContext.Session.SetString("FullName", user.FullName ?? "Admin");
            HttpContext.Session.SetString("Role", "Admin");

            Log("ADMIN_LOGIN", $"Admin đăng nhập từ {ClientIp}");

            return RedirectToAction("Index");
        }

        public IActionResult Logout()
        {
            Log("ADMIN_LOGOUT", "Admin đăng xuất");
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // ─── USER MANAGEMENT ───

        [HttpPost]
        public async Task<IActionResult> DeleteUser(int id)
        {
            if (!IsAdmin) return Forbid();

            var user = await _db.Users.FindAsync(id);
            if (user != null && user.Role != "Admin")
            {
                Log("DELETE_USER", $"Xóa người dùng: {user.Username}");
                _db.Users.Remove(user); // Cascade xóa tasks
                await _db.SaveChangesAsync();
                TempData["Success"] = $"Đã xóa người dùng '{user.Username}'!";
            }
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> UnlockUser(int id)
        {
            if (!IsAdmin) return Forbid();

            var user = await _db.Users.FindAsync(id);
            if (user != null)
            {
                user.IsLocked = false;
                user.LoginAttempts = 0;
                await _db.SaveChangesAsync();
                Log("UNLOCK_USER", $"Mở khóa tài khoản: {user.Username}");
                TempData["Success"] = $"Đã mở khóa tài khoản '{user.Username}'!";
            }
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> LockUser(int id)
        {
            if (!IsAdmin) return Forbid();

            var user = await _db.Users.FindAsync(id);
            if (user != null && user.Role != "Admin")
            {
                user.IsLocked = true;
                await _db.SaveChangesAsync();
                Log("LOCK_USER", $"Khóa tài khoản: {user.Username}");
                TempData["Success"] = $"Đã khóa tài khoản '{user.Username}'!";
            }
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(int id)
        {
            if (!IsAdmin) return Forbid();

            var user = await _db.Users.FindAsync(id);
            if (user != null && user.Role != "Admin")
            {
                var newPass = "123456";
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPass);
                user.IsLocked = false;
                user.LoginAttempts = 0;
                await _db.SaveChangesAsync();
                Log("RESET_PASSWORD", $"Reset mật khẩu cho: {user.Username}");
                TempData["Success"] = $"Đã reset mật khẩu '{user.Username}' về '123456'!";
            }
            return RedirectToAction("Index");
        }

        // ─── TASK MANAGEMENT ──────────────────────────────────────────────────────

        [HttpPost]
        public async Task<IActionResult> DeleteTask(int id)
        {
            if (!IsAdmin) return Forbid();

            var task = await _db.Tasks.FindAsync(id);
            if (task != null)
            {
                Log("ADMIN_DELETE_TASK", $"Admin xóa công việc: {task.Title}");
                _db.Tasks.Remove(task);
                await _db.SaveChangesAsync();
                TempData["Success"] = "Đã xóa công việc!";
            }
            return RedirectToAction("Index");
        }

        // ─── ACTIVITY LOG ───

        public async Task<IActionResult> ActivityLogs(int page = 1)
        {
            if (!IsAdmin) return RedirectToAction("Login");

            int pageSize = 30;
            var total = await _db.ActivityLogs.CountAsync();
            var logs = await _db.ActivityLogs
                .Include(a => a.User)
                .OrderByDescending(a => a.CreatedAt)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.Logs = logs;
            ViewBag.Page = page;
            ViewBag.TotalPages = (int)Math.Ceiling((double)total / pageSize);
            return View();
        }
    }
}

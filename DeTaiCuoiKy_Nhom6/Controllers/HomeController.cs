using CsvHelper;
using DeTaiCuoiKy_Nhom6.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using DeTaiCuoiKy_Nhom6.Data;
using DeTaiCuoiKy_Nhom6.Models;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Globalization;

namespace DeTaiCuoiKy_Nhom6.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public HomeController(ApplicationDbContext db, IHttpContextAccessor httpContextAccessor)
        {
            _db = db;
            _httpContextAccessor = httpContextAccessor;
        }

        // ─── Helpers ───

        private int? CurrentUserId => HttpContext.Session.GetInt32("UserId");
        private string CurrentRole => HttpContext.Session.GetString("Role") ?? "User";
        private string ClientIp => _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        private void Log(int? userId, string action, string? desc = null)
        {
            _db.ActivityLogs.Add(new ActivityLog
            {
                UserId = userId,
                Action = action,
                Description = desc,
                IpAddress = ClientIp,
                CreatedAt = DateTime.Now
            });
            _db.SaveChanges();
        }

        private bool RequireLogin()
        {
            return CurrentUserId.HasValue;
        }

        // ─── INDEX ───

        public async Task<IActionResult> Index(
            string? search, string? priority, string? category,
            string? status, string? sort)
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            var query = _db.Tasks
                .Include(t => t.User)
                .Where(t => t.UserId == CurrentUserId!.Value);

            // Search
            if (!string.IsNullOrWhiteSpace(search))
                query = query.Where(t => t.Title.Contains(search) || (t.Description != null && t.Description.Contains(search)));

            // Filter priority
            if (!string.IsNullOrWhiteSpace(priority))
                query = query.Where(t => t.Priority == priority);

            // Filter category
            if (!string.IsNullOrWhiteSpace(category))
                query = query.Where(t => t.Category == category);

            // Filter status
            if (status == "completed") query = query.Where(t => t.IsCompleted);
            else if (status == "pending") query = query.Where(t => !t.IsCompleted);
            else if (status == "overdue") query = query.Where(t => !t.IsCompleted && t.DueDate < DateTime.Now);

            // Sort
            query = sort switch
            {
                "title" => query.OrderBy(t => t.Title),
                "priority" => query.OrderByDescending(t => t.Priority),
                "duedate" => query.OrderBy(t => t.DueDate),
                _ => query.OrderByDescending(t => t.CreatedAt)
            };

            var tasks = await query.ToListAsync();

            // Stats
            var allTasks = await _db.Tasks.Where(t => t.UserId == CurrentUserId!.Value).ToListAsync();
            ViewBag.TotalTasks = allTasks.Count;
            ViewBag.CompletedTasks = allTasks.Count(t => t.IsCompleted);
            ViewBag.PendingTasks = allTasks.Count(t => !t.IsCompleted);
            ViewBag.OverdueTasks = allTasks.Count(t => t.IsOverdue);

            // Completion rate
            ViewBag.CompletionRate = allTasks.Count > 0
                ? (int)Math.Round((double)allTasks.Count(t => t.IsCompleted) / allTasks.Count * 100)
                : 0;

            // Categories for filter
            ViewBag.Categories = await _db.Tasks
                .Where(t => t.UserId == CurrentUserId!.Value)
                .Select(t => t.Category)
                .Distinct()
                .ToListAsync();

            ViewBag.Username = HttpContext.Session.GetString("Username");
            ViewBag.FullName = HttpContext.Session.GetString("FullName");
            ViewBag.Tasks = tasks;
            ViewBag.Search = search;
            ViewBag.Priority = priority;
            ViewBag.Category = category;
            ViewBag.Status = status;
            ViewBag.Sort = sort;

            return View();
        }

        // ─── LOGIN ───

        [HttpGet]
        public IActionResult Login()
        {
            if (RequireLogin()) return RedirectToAction("Index");
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                ViewBag.Error = "Vui lòng nhập đầy đủ thông tin!";
                ViewBag.Username = username;
                return View();
            }

            var clean = username.Trim().ToLower();
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username.ToLower() == clean);

            if (user == null)
            {
                ViewBag.Error = "Tên đăng nhập hoặc mật khẩu không đúng!";
                ViewBag.Username = username;
                return View();
            }

            if (user.IsLocked)
            {
                ViewBag.Error = "Tài khoản đã bị khóa! Vui lòng liên hệ Admin.";
                ViewBag.Username = username;
                return View();
            }

            bool valid = BCrypt.Net.BCrypt.Verify(password.Trim(), user.PasswordHash);

            if (!valid)
            {
                user.LoginAttempts++;
                if (user.LoginAttempts >= 5)
                {
                    user.IsLocked = true;
                    ViewBag.Error = "Tài khoản bị khóa do nhập sai mật khẩu 5 lần!";
                    Log(user.Id, "LOCK_ACCOUNT", $"Khóa tài khoản {user.Username}");
                }
                else
                {
                    ViewBag.Error = $"Mật khẩu không đúng! Còn {5 - user.LoginAttempts} lần thử.";
                }
                await _db.SaveChangesAsync();
                ViewBag.Username = username;
                return View();
            }

            // Đăng nhập thành công
            user.LoginAttempts = 0;
            user.LastLoginAt = DateTime.Now;
            await _db.SaveChangesAsync();

            HttpContext.Session.SetInt32("UserId", user.Id);
            HttpContext.Session.SetString("Username", user.Username);
            HttpContext.Session.SetString("FullName", user.FullName ?? user.Username);
            HttpContext.Session.SetString("Role", user.Role);

            Log(user.Id, "LOGIN", $"Đăng nhập thành công từ {ClientIp}");

            // Redirect theo role
            if (user.Role == "Admin")
                return RedirectToAction("Index", "Admin");

            return RedirectToAction("Index");
        }

        // ─── REGISTER ───

        [HttpGet]
        public IActionResult Register()
        {
            if (RequireLogin()) return RedirectToAction("Index");
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(string username, string password, string confirmPassword, string? fullName, string? email)
        {
            var cleanUser = username?.Trim() ?? "";
            var cleanPass = password?.Trim() ?? "";

            ViewBag.Username = cleanUser;
            ViewBag.FullName = fullName;
            ViewBag.Email = email;

            if (string.IsNullOrEmpty(cleanUser) || string.IsNullOrEmpty(cleanPass))
            {
                ViewBag.Error = "Vui lòng nhập đầy đủ thông tin!";
                return View();
            }

            if (cleanPass.Length < 6)
            {
                ViewBag.Error = "Mật khẩu phải có ít nhất 6 ký tự!";
                return View();
            }

            if (cleanPass != (confirmPassword?.Trim() ?? ""))
            {
                ViewBag.Error = "Mật khẩu xác nhận không khớp!";
                return View();
            }

            bool exists = await _db.Users.AnyAsync(u => u.Username.ToLower() == cleanUser.ToLower());
            if (exists)
            {
                ViewBag.Error = "Tên đăng nhập đã tồn tại!";
                return View();
            }

            var newUser = new User
            {
                Username = cleanUser,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(cleanPass),
                FullName = string.IsNullOrEmpty(fullName) ? null : fullName.Trim(),
                Email = string.IsNullOrEmpty(email) ? null : email.Trim(),
                Role = "User",
                CreatedAt = DateTime.Now
            };

            _db.Users.Add(newUser);
            await _db.SaveChangesAsync();

            Log(newUser.Id, "REGISTER", $"Đăng ký tài khoản mới: {cleanUser}");

            TempData["Success"] = $"Đăng ký tài khoản '{cleanUser}' thành công!";
            return RedirectToAction("Login");
        }

        // ─── LOGOUT ───

        public IActionResult Logout()
        {
            if (CurrentUserId.HasValue)
                Log(CurrentUserId, "LOGOUT", "Đăng xuất");
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // ─── TASK CRUD ───

        [HttpPost]
        public async Task<IActionResult> AddTask(TaskItem task)
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            task.UserId = CurrentUserId!.Value;
            task.CreatedAt = DateTime.Now;
            task.IsCompleted = false;

            _db.Tasks.Add(task);
            await _db.SaveChangesAsync();

            Log(CurrentUserId, "ADD_TASK", $"Thêm công việc: {task.Title}");
            TempData["Success"] = "Thêm công việc thành công!";
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> ToggleComplete(int id)
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            var task = await _db.Tasks.FirstOrDefaultAsync(t => t.Id == id && t.UserId == CurrentUserId!.Value);
            if (task != null)
            {
                task.IsCompleted = !task.IsCompleted;
                task.CompletedAt = task.IsCompleted ? DateTime.Now : null;
                await _db.SaveChangesAsync();

                var msg = task.IsCompleted ? "Đánh dấu hoàn thành" : "Bỏ đánh dấu hoàn thành";
                Log(CurrentUserId, "TOGGLE_TASK", $"{msg}: {task.Title}");
                TempData["Success"] = task.IsCompleted ? "Đã đánh dấu hoàn thành!" : "Đã bỏ đánh dấu hoàn thành!";
            }
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> DeleteTask(int id)
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            var task = await _db.Tasks.FirstOrDefaultAsync(t => t.Id == id && t.UserId == CurrentUserId!.Value);
            if (task != null)
            {
                Log(CurrentUserId, "DELETE_TASK", $"Xóa công việc: {task.Title}");
                _db.Tasks.Remove(task);
                await _db.SaveChangesAsync();
                TempData["Success"] = "Đã xóa công việc!";
            }
            return RedirectToAction("Index");
        }

        [HttpGet]
        public async Task<IActionResult> EditTask(int id)
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            var task = await _db.Tasks.FirstOrDefaultAsync(t => t.Id == id && t.UserId == CurrentUserId!.Value);
            if (task == null) return RedirectToAction("Index");

            ViewBag.Username = HttpContext.Session.GetString("Username");
            return View(task);
        }

        [HttpPost]
        public async Task<IActionResult> EditTask(TaskItem task)
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            var existing = await _db.Tasks.FirstOrDefaultAsync(t => t.Id == task.Id && t.UserId == CurrentUserId!.Value);
            if (existing != null)
            {
                existing.Title = task.Title;
                existing.Description = task.Description;
                existing.Priority = task.Priority;
                existing.Category = task.Category;
                existing.DueDate = task.DueDate;
                await _db.SaveChangesAsync();

                Log(CurrentUserId, "EDIT_TASK", $"Sửa công việc: {existing.Title}");
                TempData["Success"] = "Cập nhật công việc thành công!";
            }
            return RedirectToAction("Index");
        }

        // ─── EXPORT CSV ───

        public async Task<IActionResult> ExportCsv()
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            var tasks = await _db.Tasks
                .Where(t => t.UserId == CurrentUserId!.Value)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();

            var stream = new MemoryStream();
            using (var writer = new StreamWriter(stream, leaveOpen: true))
            using (var csv = new CsvWriter(writer, CultureInfo.InvariantCulture))
            {
                csv.WriteHeader<TaskExportDto>();
                csv.NextRecord();
                foreach (var t in tasks)
                {
                    csv.WriteRecord(new TaskExportDto
                    {
                        TieuDe = t.Title,
                        MoTa = t.Description ?? "",
                        DanhMuc = t.Category,
                        UuTien = t.Priority == "high" ? "Cao" : t.Priority == "medium" ? "Trung bình" : "Thấp",
                        HanHoanThanh = t.DueDate?.ToString("dd/MM/yyyy") ?? "",
                        TrangThai = t.IsCompleted ? "Hoàn thành" : (t.IsOverdue ? "Quá hạn" : "Đang thực hiện"),
                        NgayTao = t.CreatedAt.ToString("dd/MM/yyyy HH:mm")
                    });
                    csv.NextRecord();
                }
            }

            stream.Position = 0;
            Log(CurrentUserId, "EXPORT_CSV", "Xuất danh sách công việc");
            return File(stream, "text/csv", $"cong_viec_{DateTime.Now:yyyyMMdd}.csv");
        }

        // ─── PROFILE ───

        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            var user = await _db.Users.FindAsync(CurrentUserId!.Value);
            if (user == null) return RedirectToAction("Login");

            var recentLogs = await _db.ActivityLogs
                .Where(a => a.UserId == CurrentUserId!.Value)
                .OrderByDescending(a => a.CreatedAt)
                .Take(10)
                .ToListAsync();

            ViewBag.RecentLogs = recentLogs;
            return View(user);
        }

        [HttpPost]
        public async Task<IActionResult> UpdateProfile(string fullName, string? email, string? currentPassword, string? newPassword)
        {
            if (!RequireLogin()) return RedirectToAction("Login");

            var user = await _db.Users.FindAsync(CurrentUserId!.Value);
            if (user == null) return RedirectToAction("Login");

            user.FullName = string.IsNullOrEmpty(fullName) ? user.FullName : fullName.Trim();
            user.Email = string.IsNullOrEmpty(email) ? user.Email : email.Trim();

            // Đổi mật khẩu (nếu có)
            if (!string.IsNullOrEmpty(newPassword))
            {
                if (string.IsNullOrEmpty(currentPassword) || !BCrypt.Net.BCrypt.Verify(currentPassword, user.PasswordHash))
                {
                    TempData["Error"] = "Mật khẩu hiện tại không đúng!";
                    return RedirectToAction("Profile");
                }
                if (newPassword.Length < 6)
                {
                    TempData["Error"] = "Mật khẩu mới phải có ít nhất 6 ký tự!";
                    return RedirectToAction("Profile");
                }
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
                Log(CurrentUserId, "CHANGE_PASSWORD", "Đổi mật khẩu thành công");
            }

            HttpContext.Session.SetString("FullName", user.FullName ?? user.Username);
            await _db.SaveChangesAsync();
            Log(CurrentUserId, "UPDATE_PROFILE", "Cập nhật thông tin cá nhân");
            TempData["Success"] = "Cập nhật thành công!";
            return RedirectToAction("Profile");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }

    // DTO for CSV export
    public class TaskExportDto
    {
        public string TieuDe { get; set; } = "";
        public string MoTa { get; set; } = "";
        public string DanhMuc { get; set; } = "";
        public string UuTien { get; set; } = "";
        public string HanHoanThanh { get; set; } = "";
        public string TrangThai { get; set; } = "";
        public string NgayTao { get; set; } = "";
    }
}

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using DeTaiCuoiKy_Nhom6.Models;
using DeTaiCuoiKy_Nhom6.Services;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace DeTaiCuoiKy_Nhom6.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly EmailSender _emailSender;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, EmailSender emailSender, IWebHostEnvironment webHostEnvironment)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailSender = emailSender;
            _webHostEnvironment = webHostEnvironment;
        }

        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, HoTen = model.HoTen };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    if (!await _roleManager.RoleExistsAsync("Admin")) await _roleManager.CreateAsync(new IdentityRole("Admin"));
                    if (!await _roleManager.RoleExistsAsync("User")) await _roleManager.CreateAsync(new IdentityRole("User"));

                    string selectedRole = string.IsNullOrEmpty(model.Role) ? "User" : model.Role;
                    await _userManager.AddToRoleAsync(user, selectedRole);

                    // Tạo mã xác minh ngẫu nhiên gồm 6 chữ số
                    var randomCode = new Random().Next(100000, 999999).ToString();

                    // Lưu tạm thông tin vào Session/TempData để phục vụ bước xác minh
                    TempData["PendingUserId"] = user.Id;
                    TempData["VerificationCode"] = randomCode;

                    // Gửi mail thực tế
                    try
                    {
                        await _emailSender.SendVerificationCodeAsync(user.Email!, randomCode);
                    }
                    catch { /* Bỏ qua nếu chưa cấu hình đúng SMTP để không chết luồng */ }

                    return RedirectToAction("VerifyEmail");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult VerifyEmail() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyEmail(string code)
        {
            var targetCode = TempData["VerificationCode"]?.ToString();
            var userId = TempData["PendingUserId"]?.ToString();

            if (targetCode == code && !string.IsNullOrEmpty(userId))
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.EmailConfirmed = true;
                    await _userManager.UpdateAsync(user);
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "CongViec");
                }
            }

            ModelState.AddModelError(string.Empty, "Mã xác minh không chính xác hoặc đã hết hạn!");
            // Giữ lại dữ liệu TempData cho lần nhập kế tiếp
            TempData.Keep();
            return View();
        }

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded) return LocalRedirect(returnUrl);
                ModelState.AddModelError(string.Empty, "Tài khoản hoặc mật khẩu không chính xác.");
            }
            return View(model);
        }

        // --- ĐĂNG NHẬP GOOGLE AUTH CORES ---
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string? returnUrl = null)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
        {
            returnUrl ??= Url.Content("~/");
            if (remoteError != null) return RedirectToAction("Login");

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null) return RedirectToAction("Login");

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded) return LocalRedirect(returnUrl);

            // Nếu tài khoản Google chưa từng tồn tại trong DB hệ thống -> Tiến hành tự động tạo mới
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var name = info.Principal.FindFirstValue(ClaimTypes.Name);

            if (email != null)
            {
                var user = new ApplicationUser { UserName = email, Email = email, HoTen = name ?? "User Google", EmailConfirmed = true };
                var createResult = await _userManager.CreateAsync(user);
                if (createResult.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "User");
                    await _userManager.AddLoginAsync(user, info);
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnUrl);
                }
            }
            return RedirectToAction("Login");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

        // --- TÍNH NĂNG XEM THÔNG TIN VÀ TẢI LÊN NHIỀU ẢNH ĐẠI DIỆN ---
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();
            return View(user);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UploadAvatars(List<IFormFile> avatarFiles)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound();

            if (avatarFiles != null && avatarFiles.Count > 0)
            {
                string uploadFolder = Path.Combine(_webHostEnvironment.WebRootPath, "uploads");
                if (!Directory.Exists(uploadFolder)) Directory.CreateDirectory(uploadFolder);

                List<string> savedPaths = new List<string>();

                // Quét qua từng file được chọn (Hỗ trợ chọn 1 hoặc nhiều file cùng lúc)
                foreach (var file in avatarFiles)
                {
                    if (file.Length > 0)
                    {
                        string uniqueFileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(file.FileName);
                        string filePath = Path.Combine(uploadFolder, uniqueFileName);
                        using (var fileStream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(fileStream);
                        }
                        savedPaths.Add("/uploads/" + uniqueFileName);
                    }
                }

                // Nối chuỗi danh sách ảnh mới lưu vào DB
                if (savedPaths.Count > 0)
                {
                    string newAvatarsData = string.Join(";", savedPaths);
                    user.Avatars = string.IsNullOrEmpty(user.Avatars) ? newAvatarsData : user.Avatars + ";" + newAvatarsData;
                    await _userManager.UpdateAsync(user);
                    TempData["ToastMessage"] = "Đã cập nhật bộ sưu tập ảnh đại diện thành công! 🖼️";
                }
            }
            return RedirectToAction("Profile");
        }

        // --- CÁC TÍNH NĂNG ĐỘC QUYỀN CỦA ADMIN ĐỂ TEST ACCESS DENIED ---
        [Authorize(Roles = "Admin")]
        [HttpGet]
        public IActionResult AdminSettings() => View();

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public IActionResult UserManagement() => View();

        [HttpGet]
        public IActionResult AccessDenied() => View();
    }

    // --- VIEW MODELS ---
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "Vui lòng nhập Email")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Vui lòng nhập Họ tên")]
        public string HoTen { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mật khẩu bắt buộc")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Vui lòng chọn vai trò")]
        public string Role { get; set; } = "User";
    }

    public class LoginViewModel
    {
        [Required(ErrorMessage = "Vui lòng nhập Email")]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Vui lòng nhập mật khẩu")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        public bool RememberMe { get; set; }
    }
}
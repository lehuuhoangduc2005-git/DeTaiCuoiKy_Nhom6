using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using DeTaiCuoiKy_Nhom6.Data;
using DeTaiCuoiKy_Nhom6.Models;

namespace DeTaiCuoiKy_Nhom6.Controllers
{
    [Authorize] // Bắt buộc đăng nhập mới được truy cập các chức năng trong Controller này
    public class CongViecController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public CongViecController(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        // Hàm helper lấy thông tin User hiện tại một cách an toàn
        private Task<ApplicationUser> GetCurrentUserAsync() => _userManager.GetUserAsync(HttpContext.User);

        // GET: CongViec
        public async Task<IActionResult> Index(string? searchString, string? statusFilter, string? typeFilter, string? timeFilter)
        {
            var user = await GetCurrentUserAsync();
            if (user == null) return Challenge(); // Phòng hờ lỗi Session/Cookie đột ngột hết hạn

            var roles = await _userManager.GetRolesAsync(user);
            var isAdmin = roles.Contains("Admin");

            // PHÂN QUYỀN TRUY VẤN: Admin thấy tất cả, User chỉ thấy việc của mình
            IQueryable<CongViec> congViecs = isAdmin
                ? _context.CongViecs
                : _context.CongViecs.Where(c => c.UserId == user.Id);

            // --- TÍNH TOÁN SỐ LIỆU THỐNG KÊ (Dựa trên tập dữ liệu được phép xem) ---
            var todayDate = DateTime.Today;
            ViewData["StatTotal"] = await congViecs.CountAsync();
            ViewData["StatCompleted"] = await congViecs.CountAsync(c => c.DaHoanThanh);
            ViewData["StatOverdue"] = await congViecs.CountAsync(c => c.NgayHetHan.Date < todayDate && !c.DaHoanThanh);

            // Lưu bộ lọc ra View để giữ trạng thái trên thanh Select/Input
            ViewData["CurrentSearch"] = searchString;
            ViewData["CurrentStatus"] = statusFilter;
            ViewData["CurrentType"] = typeFilter;
            ViewData["CurrentTime"] = timeFilter;

            // 1. Tìm kiếm theo tên hoặc mô tả
            if (!string.IsNullOrEmpty(searchString))
            {
                congViecs = congViecs.Where(s => s.TenCongViec.Contains(searchString) || (s.MoTa != null && s.MoTa.Contains(searchString)));
            }

            // 2. Lọc theo trạng thái
            if (!string.IsNullOrEmpty(statusFilter))
            {
                bool isCompleted = statusFilter == "completed";
                congViecs = congViecs.Where(s => s.DaHoanThanh == isCompleted);
            }

            // 3. Lọc theo Phân loại
            if (!string.IsNullOrEmpty(typeFilter))
            {
                congViecs = congViecs.Where(s => s.PhanLoai == typeFilter);
            }

            // 4. Lọc theo thời gian
            if (!string.IsNullOrEmpty(timeFilter))
            {
                if (timeFilter == "today")
                    congViecs = congViecs.Where(s => s.NgayHetHan.Date == todayDate);
                else if (timeFilter == "overdue")
                    congViecs = congViecs.Where(s => s.NgayHetHan.Date < todayDate && !s.DaHoanThanh);
                else if (timeFilter == "upcoming")
                    congViecs = congViecs.Where(s => s.NgayHetHan.Date > todayDate);
            }

            var danhSach = await congViecs.OrderBy(c => c.NgayHetHan).ToListAsync();
            return View(danhSach);
        }

        // POST: CongViec/ToggleStatus/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleStatus(int id)
        {
            var user = await GetCurrentUserAsync();
            if (user == null) return Challenge();

            var congViec = await _context.CongViecs.FindAsync(id);
            if (congViec == null) return NotFound();

            var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");

            // Kiểm tra quyền: Phải là chủ sở hữu HOẶC là Admin mới được đổi trạng thái
            if (congViec.UserId == user.Id || isAdmin)
            {
                congViec.DaHoanThanh = !congViec.DaHoanThanh;
                await _context.SaveChangesAsync();
                TempData["ToastMessage"] = congViec.DaHoanThanh ? "Đã đánh dấu HOÀN THÀNH công việc! 🎉" : "Đã chuyển việc về trạng thái CHƯA XONG! 🕒";
            }
            else
            {
                return RedirectToAction("AccessDenied", "Account");
            }
            return RedirectToAction(nameof(Index));
        }

        // GET: CongViec/Create
        public IActionResult Create() => View();

        // POST: CongViec/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,TenCongViec,MoTa,NgayHetHan,DaHoanThanh,PhanLoai")] CongViec congViec)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                if (user == null) return Challenge();

                congViec.UserId = user.Id; // Đóng dấu chủ sở hữu công việc chính xác bằng ID từ hệ thống

                _context.Add(congViec);
                await _context.SaveChangesAsync();
                TempData["ToastMessage"] = "Thêm mới công việc thành công rực rỡ! 🚀";
                return RedirectToAction(nameof(Index));
            }
            return View(congViec);
        }

        // GET: CongViec/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null) return NotFound();

            var user = await GetCurrentUserAsync();
            if (user == null) return Challenge();

            var congViec = await _context.CongViecs.FindAsync(id);
            if (congViec == null) return NotFound();

            // Chặn truy cập GET nếu không phải chủ nhân và không phải Admin
            if (congViec.UserId != user.Id && !await _userManager.IsInRoleAsync(user, "Admin"))
            {
                return RedirectToAction("AccessDenied", "Account");
            }

            return View(congViec);
        }

        // POST: CongViec/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,TenCongViec,MoTa,NgayHetHan,DaHoanThanh,PhanLoai")] CongViec congViec)
        {
            if (id != congViec.Id) return NotFound();

            var user = await GetCurrentUserAsync();
            if (user == null) return Challenge();

            // Lấy công việc gốc từ Database lên để kiểm tra quyền sở hữu (Chống Hack Overposting)
            var bieuMauGoc = await _context.CongViecs.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id);
            if (bieuMauGoc == null) return NotFound();

            var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");

            // BẢO MẬT: Chặn không cho lưu nếu User thường cố tình gửi request chỉnh sửa công việc của người khác
            if (bieuMauGoc.UserId != user.Id && !isAdmin)
            {
                return RedirectToAction("AccessDenied", "Account");
            }

            if (ModelState.IsValid)
            {
                try
                {
                    // Luôn giữ nguyên UserId gốc, không để dữ liệu từ Client đè bậy bạ lên chủ sở hữu
                    congViec.UserId = bieuMauGoc.UserId;

                    _context.Update(congViec);
                    await _context.SaveChangesAsync();
                    TempData["ToastMessage"] = "Cập nhật dữ liệu công việc thành công! 💾";
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!CongViecExists(congViec.Id)) return NotFound();
                    else throw;
                }
                return RedirectToAction(nameof(Index));
            }
            return View(congViec);
        }

        // GET: CongViec/Delete/5 (CHỈ ADMIN MỚI ĐƯỢC XÓA)
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null) return NotFound();
            var congViec = await _context.CongViecs.FirstOrDefaultAsync(m => m.Id == id);
            if (congViec == null) return NotFound();
            return View(congViec);
        }

        // POST: CongViec/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var congViec = await _context.CongViecs.FindAsync(id);
            if (congViec != null)
            {
                _context.CongViecs.Remove(congViec);
                await _context.SaveChangesAsync();
                TempData["ToastMessage"] = "Đã xóa công việc khỏi hệ thống! 🗑️";
            }
            return RedirectToAction(nameof(Index));
        }

        private bool CongViecExists(int id)
        {
            return _context.CongViecs.Any(e => e.Id == id);
        }
    }
}
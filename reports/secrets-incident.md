# Secret giả trong lịch sử Git

- Scanner: Gitleaks **8.30.1**, binary từ release chính thức, đặt ở `.venv/tools/gitleaks` (không nộp binary).
- Commit: `1bdd849922156c868a5ee9293d68f5b72e242d2c`.
- File: `lab-fake-secret.txt:1`; rule: `lab24-synthetic-token`.
- `gitleaks git --config .gitleaks.toml --redact --verbose --report-format json --report-path reports/gitleaks-history.json .` tìm đúng **1 finding**. Exit 1 là kết quả dự kiến. Xem `gitleaks-history.json`; Secret và Match đã redact.
- `gitleaks dir --config .gitleaks.toml --redact --report-format json --report-path reports/gitleaks-current.json .`: **0 finding**, exit 0. File token không còn trong HEAD. Đây là token giả vô hiệu do đề bài cài sẵn, không phải sự cố credential thật.
- Nếu là secret thật: thu hồi/rotate ngay tại nhà cung cấp, điều tra quyền và truy cập từ thời điểm lộ, cập nhật nơi sử dụng và kiểm tra tác động; làm sạch lịch sử chỉ là bước bổ sung. Không tạo hoặc thử credential thật trong lab.
- Xoá file khỏi HEAD không thu hồi quyền của credential đã bị sao chép. Pin dependency và hash kiểm artifact cài đặt; hook quét file hiện tại giúp ngăn commit mới chứa secret. Chúng không rotate secret, không chứng minh dependency vô hại và không xoá các bản sao lịch sử.
- Hook pin repo chính thức `v8.30.1`, `gitleaks-system`, `pass_filenames: false`; entry dùng `gitleaks dir` để HEAD sạch pass dù lịch sử còn finding phục vụ bài lab. Quét lịch sử được chạy riêng như trên.

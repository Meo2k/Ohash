# ohash - Công cụ Mã hóa/Giải mã Tập tin

`ohash` là một công cụ mã hóa và giải mã tập tin qua dòng lệnh (CLI). Công cụ này sử dụng cơ chế bảo mật tương tự như SSH: kết hợp giữa mật khẩu (Passphrase) và một chuỗi ngẫu nhiên (Salt) để tạo khóa mã hóa an toàn, sau đó dùng thuật toán AES-GCM để mã hóa dữ liệu.


## Tính năng nổi bật

- **Bảo mật cao**: Sử dụng thư viện `cryptography` với chuẩn mã hóa AES-256-GCM (Authenticated Encryption) bảo mật và chống thay đổi dữ liệu.
- **Dẫn xuất khóa an toàn**: Sử dụng thuật toán PBKDF2 (HMAC-SHA256) với số vòng lặp an toàn (100.000 vòng) kết hợp với Salt ngẫu nhiên (16 bytes) để chống lại các cuộc tấn công Brute-force/Rainbow Table.
- **Xử lý tệp lớn mượt mà (Chunked Mode)**: Hỗ trợ mã hóa và giải mã dữ liệu theo từng khối (chunk). Điều này giúp tối ưu hóa bộ nhớ RAM kể cả khi mã hóa các tập tin dung lượng cực lớn.
- **Hai chế độ mã hóa**:
  - **Chunked Mode (`--cnk`)**: (Mặc định) Mã hóa từng khối dữ liệu với Nonce và Tag (xác thực) riêng biệt. An toàn cho file siêu lớn.
  - **Block Mode (`--bck`)**: Mã hóa toàn bộ file dùng chung một Nonce duy nhất.
- **Trực quan dễ dùng**: Hiển thị thanh tiến trình (progress bar) chi tiết trong quá trình đọc/ghi file.
- **Bảo mật mật khẩu**: Hỗ trợ nhận mật khẩu từ biến môi trường `OHASH_PASS` (thích hợp cho luồng tự động hóa/cron job) hoặc nhập trực tiếp từ bàn phím.

## Yêu cầu hệ thống

- `uv` (Trình quản lý gói Python hiện đại, tốc độ cao)

Đầu tiên, hãy cài đặt các dependencies (chỉ mất vài giây với uv):
```bash
uv sync
```

## Cài đặt ứng dụng Global (Khuyên dùng)

Bạn có thể cài đặt `ohash` như một công cụ dòng lệnh (Global CLI) trên toàn hệ thống để sử dụng ở bất cứ đâu mà không cần phụ thuộc vào thư mục chứa code:

```bash
uv tool install .
```

Sau khi cài đặt xong, bạn có thể gọi trực tiếp lệnh `ohash` ở mọi nơi:
```bash
ohash e tailieu.pdf
ohash d tailieu.pdf.enc
```

## Cấu trúc File đã mã hóa

Khi một tệp được mã hóa, nó được thêm một phần Header ở đầu file. Ở phiên bản hiện tại, cấu trúc Header bao gồm:
1. `MAGIC_NUMBER`: `OHASH` (5 bytes) - Dấu hiệu nhận biết tệp được mã hóa bởi công cụ này (trước đây là `MYDB`).
2. `SALT`: Chuỗi ngẫu nhiên 16 bytes.
3. `ROUNDS`: Số vòng lặp PBKDF2 (4 bytes).
4. `FILE_SIZE`: Kích thước file gốc (8 bytes).
5. `NONCE`: Chuỗi ngẫu nhiên 12 bytes dùng cho thuật toán AES-GCM.
6. `MODE`: Chế độ mã hóa được sử dụng (1 byte - Block hoặc Chunked).
7. Phần còn lại là dữ liệu (Ciphertext).

## Cú pháp sử dụng

Nếu bạn đã cài đặt ứng dụng Global (`uv tool install .`), bạn có thể gọi trực tiếp lệnh `ohash`. Nếu không, bạn vẫn có thể chạy qua lệnh `uv run ohash`.

### 1. Mã hóa tập tin (Encrypt)

```bash
# Sử dụng Block Mode (Mặc định)
ohash e <file_cần_mã_hóa> [file_đầu_ra]

# Sử dụng Chunked Mode 
ohash e <file_cần_mã_hóa> --cnk [file_đầu_ra]
```
*Lưu ý: Nếu không truyền `[file_đầu_ra]`, công cụ sẽ mặc định ghi đè và xóa tập tin gốc.*

### 2. Giải mã tập tin (Decrypt)

Chương trình sẽ tự động nhận diện chế độ mã hóa (Block/Chunked) được lưu trong header để giải mã đúng cách:

```bash
ohash d <file_đã_mã_hóa> [file_đầu_ra]
```

### 3. Thiết lập mật khẩu tự động qua Biến môi trường

Bạn có thể truyền mật khẩu qua biến môi trường `OHASH_PASS` để không phải nhập tay mỗi lần chạy:

```bash
export OHASH_PASS="mat-khau-bi-mat-cua-ban"
ohash e baocao.pdf
```

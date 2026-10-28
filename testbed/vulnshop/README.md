# VulnShop

> **Ứng dụng này cố ý có lỗ hổng. Chỉ chạy cục bộ, không deploy, không đưa lên mạng.**
> *This application is intentionally vulnerable. Run it on loopback only. Never deploy it.*

Web app giả lập (Flask + SQLite) dùng làm target kiểm thử có ground truth chính xác cho SafetyWebbing
và để luyện code review. Thiết kế đầy đủ: [`docs/vulnshop-plan.md`](../../docs/vulnshop-plan.md).

| | |
|---|---|
| Lỗ hổng cố ý | 14 (13 khai thác được qua HTTP + 1 chỉ thấy trong code) |
| Điều khiển an toàn (bản đã vá) | 8 |
| Điểm yếu chấp nhận (`accepted_weakness`) | 8 |
| Mọi thứ khác | không được có lỗ hổng khai thác được |

## Chạy

```bash
cd testbed/vulnshop
pip install -r requirements.txt
python -m vulnshop            # http://127.0.0.1:5050, dịch vụ nội bộ giả ở cổng 5051
```

`PORT` đổi cổng (cần cả `PORT` và `PORT+1` rảnh, nếu không app từ chối khởi động). `HOST` chỉ nhận
`127.0.0.1` hoặc `localhost`; giá trị khác làm app thoát với lỗi, không có cờ tắt.

`python reset.py` dựng lại toàn bộ `data/` (DB, khoá token, file sandbox, `oracle.jsonl`). `python -m vulnshop`
tự gọi nó nếu `data/` chưa có. Không có endpoint HTTP nào để reset.

Docker (tuỳ chọn, Linux): app chỉ bind loopback nên không dùng `-p`; dùng `docker run --network host vulnshop`.

## Kiểm chứng

```bash
python -m vulnshop &                 # hoặc chạy ở terminal khác
python verify_ground_truth.py        # bảng PASS/FAIL; thoát khác 0 nếu số liệu lệch
python -m pytest tests safetywebbing/tests
```

`verify_ground_truth.py` chạy một PoC cho mỗi lỗ hổng HTTP và xác nhận bằng `data/oracle.jsonl`, kiểm tra
tĩnh mục chỉ-có-trong-code, và chứng minh payload của từng điều khiển an toàn bị từ chối mà không sinh dòng
oracle. Nó cũng đối chiếu ID với file đáp án nếu tìm thấy.

## Ràng buộc an toàn

- Chỉ bind `127.0.0.1`; từ chối request có `Host` khác `127.0.0.1`/`localhost` (chống DNS rebinding).
- Toàn bộ dữ liệu là dữ liệu giả sinh cố định; không API key, không gọi mạng ra ngoài.
- Không có shell, `eval`, `exec` hay `subprocess`. Chỉ ghi trong `testbed/vulnshop/data/` (đã git-ignore).
- Đọc file chỉ trong `data/sandbox/` (cây đường dẫn ảo, toàn file mồi). Không có đường tới file hệ thống.
- Các truy vấn nối chuỗi chạy trên kết nối SQLite **chỉ đọc**, có giới hạn thời gian và kích thước.
- Chức năng "fetch" chỉ gọi được `127.0.0.1`/`localhost`, **mọi cổng**, không theo redirect.

**Lưu ý SSRF:** vì cho phép mọi cổng loopback, endpoint đó có thể chạm các dịch vụ khác đang nghe trên
loopback của máy (ví dụ UI SafetyWebbing). Hãy chạy VulnShop trên máy không có dịch vụ nhạy cảm ở loopback.

## Dùng cho test review mù

Phần mã đưa cho người review không nên gồm `vulnshop/telemetry.py` (duy nhất nhắc tới ID/cờ),
`verify_ground_truth.py`, `safetywebbing/` (đáp án) và `docs/vulnshop-plan.md`.
Tên gói `vulnshop` và biểu ngữ cảnh báo là ngoại lệ có chủ đích (yêu cầu A10).

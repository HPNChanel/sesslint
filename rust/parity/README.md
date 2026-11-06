# Khung parity

`rust/parity/run` đọc `PIN`, tạo worktree Python đúng commit đó tại `rust/parity/run-work/`, tạo venv stdlib nếu chưa có, và cài bản ghim ở chế độ editable mà không thêm dependency. Sau đó chạy `sesslint` trên một fixture tổng hợp có `contains_real_data` bằng `false`.

Binary Rust chỉ chạy khi `--rust-bin` trỏ tới một file có thật. Runner không tìm binary trên `PATH`. Khi không có đường dẫn, kết quả là `rust_exit=absent`. Runner không kết luận hai phía khớp nhau: `compare=abstain`.

## Lệnh

```text
python rust/parity/run
python rust/parity/run --fixture fixtures/sessions/minimal-valid.jsonl
python rust/parity/run --rust-bin PATH check fixtures/sessions/minimal-valid.jsonl
```

Stdout ghi pin, đường dẫn fixture tương đối, exit của Python, trạng thái Rust, và hash của stdout/stderr đã thu. Nội dung session không được in.

## PIN

Một dòng, commit `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`, kết thúc bằng LF. Byte khác với dòng đó thì runner từ chối.

## Scratch

Worktree và venv nằm ở `rust/parity/run-work/`. Không commit thư mục đó và không commit venv.

Pattern ignore (dòng này nằm trong file card được sở hữu; `.gitignore` gốc và exclude dùng chung không thuộc card này):

rust/parity/run-work/

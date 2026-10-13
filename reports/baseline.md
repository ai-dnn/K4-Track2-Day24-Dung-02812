# Baseline

1. `_naive_loop()` trong `agent/loop.py:27` chưa tạo identity, run ID, TTL hoặc ledger cho mỗi run; principal từ CLI không được baseline kiểm tra.
2. Nội dung corpus được ghép ở `agent/loop.py:32`, mock nhận diện chỉ thị ở dòng 34 rồi baseline gọi `read_customer` ở dòng 39 và `http_post` ở dòng 44 mà không có policy, còn `agent/tools.py:77` chỉ giới hạn đích localhost để lab an toàn.
3. `reports/attack-before.log:1` là POST thật tới `/reconcile` chứa record synthetic `KH-000999`, được sink ghi bởi `sink/sink.py:34`, chứng minh dữ liệu đã rời agent tới sink chứ không chỉ là kế hoạch của model.

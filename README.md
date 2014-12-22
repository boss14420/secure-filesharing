# Chương trình chia sẻ file an toàn
Chương trình cho phép các người sử dụng mã hóa các file và chia sẻ cho nhiều người dùng khác. Chỉ những người được chỉ định (thông tin được lưu trong file mã hóa) mới có thể giải mã.

## Nguyên lý hoạt động
Chương trình sử dụng cả mã hóa dùng khóa đối xứng (AES) và mã hóa dùng khóa bất đối xứng (RSAOAEP). Trong đó AES dùng để mã hóa nội dung file và RSA dùng để mã hóa khóa của AES.

Mỗi người sử dụng sẽ có một cặp khóa bí mật và khóa công khai, trong đó khóa công khai được gửi cho server (mọi người đều biết), khóa bị mất được giữ riêng không ai khác được biết.

Mỗi khi server (A) cần chia sẽ một file f cho B, C. A sẽ làm như sau:

1. Mã hóa file f bằng AES với một khóa k sinh ngẫu nhiên:

        x = AES(k, f)

2. Sử dụng khóa công khai của B, C và của chính mình để mã hóa k:

        kA = RSAOAEP(A, k)
        kB = RSAOAEP(B, k)
        kC = RSAOAEP(C, k)

3. Nối phần đã mã hóa bằng RSA với phần mã hóa bằng AES:

        y = kA || kB || kC || x

file y sẽ được chia sẻ cho B và C. B và C sẽ giải mã phần tương ứng với khóa của mình để lấy được k (sử dụng khóa bí mật):

    k = RSAOAEP-DP(B, kB)

Từ đó có thể giải mã phần còn lại bằng khóa AES k đã tính được.

Những người không phải A, B, C không có khóa bí mật nên không thể tìm được k, từ đó không thể giải mã được file đã bị mã hóa.

## Thuật toán
Chương trình này cài đặt và sử dụng các thuật toán sau:

- Thuật toán khóa mã chung: RSA-OAEP, kích thước modulo 6144 bit. Quá trình sinh khóa được song song hóa bằng OpenMP (2 luồng cho 2 số nguyên tố 3072 bit),
- Thuật toán khóa mã đối xứng: AES, khóa 128 bit. Mã hóa sử dụng CTR Mode, được song song hóa bằng OpenMP
- Thuật toán băm: SHA3-256

Để thực hiện các phép toán với số nguyên lớn, chương trình sử dụng thư viện GMPLib (https://gmplib.org/).

### Phương pháp lưu thông tin về những người được chia sẻ
Một trong những yêu cầu của chương trình chia sẻ file an toàn là người khác không thể lấy (hoặc lấy được ít) thông tin về những người được chia sẻ. Kể cả những người được chia sẻ cũng chỉ cần biết thông tin cần đủ để lấy khóa của mình chứ không được biết thông tin về những người khác.

Chương trình này sử dụng bảng băm để giúp người được chia sẻ tra cứu thông tin khóa một cách nhanh chóng (kiểm tra xem mình có được chia sẻ hay không), kết hợp với các thông tin giả để đánh lừa những người không được chia sẻ.

Để một người nào đó (ví dụ B) biết mình có được chia sẻ hay không. B sẽ làm như sau:

- dùng một hàm băm cho trước, băm tên của mình và lấy modulo theo số bucket (giá trị `num_buckets` được lưu trong file đã mã hóa) để biết khóa của mình (nếu có) ở đâu trong bảng băm, giả sử đó là bucket `b`
    
    b = hash(B) % num_buckets

- Khi đã biết được chỉ số, B duyệt qua tất cả các bản mã (đã mã hóa bằng RSA-OAEP) trong bucket `b` và thử giải mã bằng khóa bí mật của mình,
- Nếu trong bucket `b` đó tồn tại một bản mã có thể giải mã bằng khóa bí mật của B, và sinh ra được bản rõ có dạng `SHA3-256(B) || aeskey` thì `aeskey`
chính là khóa cần tìm. Đoạn `SHA3-256(B)` ở đầu dùng để nhận biết rằng đó là bản rõ được mã hóa bằng khóa công khai của B, với kích thước hàm băm 256 bit thì khả năng tồn tại một bản mã do mã hóa bằng khóa của người khác là rất thấp,
- Nếu không có bản mã nào giải mã được thành công, thì có nghĩa là B không được chia sẻ file này.

Kích thước bảng băm (số bucket) và hàm băm được chọn lựa để làm giảm thiểu xung đột nhiều nhất có thể. Ở đây :

- hàm băm được chọn là hàm `djb2` (http://www.cse.yorku.ca/~oz/hash.html),
- Só bucket được chọn là số nguyên tố nhỏ nhất lớn hơn `<số người được chia sẻ> / 0.75`.

### Giấu thông tin người dùng
Vì để ngưòi dùng có thể `nhảy` để các vị trí trong file để giải mã khóa và giải mã nội dung cần chia sẻ, nên bắt buộc phải cung cấp kích thước của từng slot, tức là qua đó tất cả mọi người đều tính được tổng số bản mã RSA-OAEP trong file. Điều này vô tinh làm lộ thông tin (chính xác) về số người dùng được chia sẻ.

Để khắc phục điều này, ta chèn vào các thông tin giả như sau: chèn một chuỗi byte ngẫu nhiên kích thước bằng một bản mã RSA-OAEP thông thường vào tất cả các bucket trống (luôn tồn tại các bucket trống vì số bucket lớn hơn số người được chia sẻ). Việc này có các ưu điểm:

1. Giấu đi thông tin chính xác về số người được chia sẻ, vì người ngoài không có cách nào để biết bản mã giả ta chèn vào có hợp lệ hay không. Tuy nhiên vẫn có thể ước lượng được khoảng giá trị vì công thức tính số bucket là công khai. 

Có một cách giải quyết triệt để là chọn số bucket bằng tổng số người dùng trong hệ thống, nhưng như vậy thì kích thước file mã hóa sẽ trở nên quá lớn.

2. Một người dùng (ví dụ D) không thể nào biết được một người khác mình (ví dụ C) có được chia sẻ hay không. Trước đây khi chưa chèn vào bucket trống, D có thể thử tính bucket tương ứng với C, nếu như rơi vào một bucket trống thì D có thể chắc chắn C không được chia sẻ. Bây giờ thì luôn trả về một bucket có ít nhất một bản mã (có thể giả), tuy nhiên D không thể biết được bản mã đó có phải là của C hay không.

3. Không ảnh hưởng đến việc giải mã của những người được chia sẻ.

Chú ý:
1. bản mã giả được chọn cần phải có giá trị nhỏ hơn modulo trong khóa công khai của tất cả người dùng, nếu không thì D có thể chắc chắn đó không phải là do khóa của C mã hóa thành,

2. Với những bucket có hơn 1 bản mã, D có thể chắc chắn rằng các bản mã này là hợp lệ (do đặc điểm của thuật toán nói trên) mặc dù không biết nó là của C hay không. Có thể chèn bản mã giả để cho tất cả bucket có kích thước bằng nhau, tuy nhiên như vậy sẽ làm kích thước file tăng lên. 

Vì vậy cho nến chọn số bucket và hàm băm thích hợp để giảm thiểu xung đột là rất quan trọng.

## Biên dịch và chạy chương trình

### Biên dịch
Yêu cầu có:

1. Trình biên dịch g++ 4.8 trở lên,
2. cmake 2.8.10 trở lên
3. GMPLib

Câu lệnh biên dịch như sau:

    cd <thư mục mã nguồn (chứa file CMakeLists.txt)
    cmake -DCMAKE_BUILD_TYPE=Release .
    make -j3

### Chạy chương trình
Sau khi biên dịch ta có 3 file thực thi:

1. `rsa_genkey`: sinh cặp khóa RSA
Cú pháp sử dụng như sau:

    ./rsa_genkey keysize name

Ví dụ:

    ./rsa_genkey 6144 admin

Sẽ sinh ra hai file `admin.publickey` và `admin.secretkey`. Xem thông tin thêm về nội
dung 2 file này tại: https://github.com/boss14420/Crypto-example/tree/master/rsaoaep

2. `encrypt`: mã hóa
Cú pháp:

    ./encrypt infile outfile [-d keydir] NAMES

Trong đó:

- `infile` là đưòng dẫn file đầu vào (chứa nội dung cần chia sẻ). Nếu bằng `-` thì đầu vào là `stdin`, có thể dùng để nhận dữ liệu từ đầu ra của chương trình khác qua đường ông lệnh (pipe),
- `outfile` là đường dẫn file đầu ra (đã mã hóa). Nếu bằng `-` thì đầu ra là `stdout`, có thể dùng để chuyển thành đầu vào cho chương trình khác qua pipe,
- `keydir` là thư mục chứa các file khóa công khai. Nếu không có tùy chọn này thì mặc định là thư mục `./keys/`

**CHÚ Ý**: trong thư mục `keydir` cần có chứa file `admin.publickey`, là khóa của người mã hóa (cần để giải mã sau này),

- NAMES là danh sách các tên ngưòi dùng (cũng là phần đầu của tên file khóa) đưọc chia sẻ.

Ví dụ:

    ./encrypt abc abc.enc user{1..10}

Sẽ mã hóa file `abc` thành file `abc.enc`, được chia sẻ cho 10 người dùng `user1`, `user2`, ..., `user10`. Trong thư mục `./keys/` cần có các file `user1.publickey`, `user2.publickey`, ...


3. `decrypt`: giải mã
Cú pháp:

    ./decrypt infile outfile username [keypath]

- `infile`: file đầu vào cần giải mã
- `outfile`: file đầu ra đã được giải mã
- `username`: tên người dùng
- `keypath`: đường dẫn đến file khóa, nếu không chỉ ra thì mặc định là `./keys/username.secretkey`

Ví dụ: giải mã file đã được mã hóa ở ví dụ trên

    ./decrypt abc.enc abc.dec user2

Nếu trong thư mục `./keys/` có chứa file `user2.secretkey` hợp lệ thì sẽ giải mã thành công.

Nếu ngưòi dùng `user11` chạy lệnh:

    ./decrypt abc.enc abc.dec2 user11

THì sẽ báo lỗi không đọc được aeskey.

### Thử nghiệm
Các kết quả sau được chạy trên máy tính Linux 64bit 3.17.4, CPU Intel Core 2 Duo SU9400 1400Hz x 2, GMPLib bản 6.0.0. 
Các phép toán mã hóa và giải mã AES đều được thực hiện trên 2 nhân CPU.

| File            | Dung lượng | File mã  | Tỉ lệ     | Thời gian     | Giải mã  | K/t MD5 |
|-----------------|------------|----------|-----------|---------------|----------|---------|
| CMakeLists.txt  | 2.8KiB     | 8.8KiB   | 3.244     | 0.01s         | 0.08s    | OK      |
| Makefile        | 15KiB      | 21KiB    | 1.431     | 0.01s         | 0.08s    | OK      |
| Earth Orbit.mp4 | 26MiB      | 26MiB    | 1.000     | 1.40s         | 1.75s    | OK      |
| dal2ova.mp4     | 285MiB     | 285MiB   | 1.000     | 14.32s        | 16.22s   | OK      |

Ta thấy với những file nhỏ thì kích thước tăng lên đáng kể do phần mã hóa khóa, nhưng với file lớn thì phần này quá nhỏ so với phần nội dung file.

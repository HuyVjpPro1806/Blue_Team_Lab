# Stolen Time - HiddenTear Lab

## **Tóm tắt sự cố**

Vào ngày 2 tháng 12 năm 2025, nhóm SOC nhận được cảnh báo về việc tải xuống một tập tin có khả năng độc hại trên máy trạm của công ty. Phân tích ban đầu cho thấy người dùng đã tải xuống phần mềm từ một nguồn không đáng tin cậy, kích hoạt các chuỗi quy trình đáng ngờ và kết nối mạng đến cơ sở hạ tầng bên ngoài.
Trong vòng vài giờ, cuộc tấn công leo thang một cách đáng kể: kẻ tấn công đã triển khai một khung điều khiển và kiểm soát tinh vi, thu thập thông tin đăng nhập miền, làm giả vé Kerberos để truy cập miền không hạn chế và di chuyển ngang sang tất cả các máy chủ quan trọng, bao gồm bộ điều khiển miền, máy chủ tập tin và máy chủ sao lưu. Cuộc tấn công lên đến đỉnh điểm bằng việc đánh cắp dữ liệu thông tin nhạy cảm của công ty, tiếp theo là triển khai phần mềm tống tiền yêu cầu khoản thanh toán Bitcoin lớn.

## Initial Access

![image.png](<images/image.png>)

Vào ngày **2025-12-02 13:56:01** User **ncooper** đã tải một file nén về đường dẫn đầy đủ **C:\Users\ncooper\Downloads\Sharp.World.Clock.9.6.7.rar** từ  **hxxps[://]edge15[.]82[.]ir[.]cdn[.]ir/soft/s/Sharp[.]World[.]Clock[.]9[.]6[.]7[.]rar?1764683751**

![image.png](<images/image 1.png>)

Sau đó giải nén và lưu các file cần thiết trong **C:\Users\ncooper\Downloads\Sharp World Clock\**

## Excution

để xác minh kẻ tấn công đã xâm nhập thành công vào hệ thống ta sẽ điều tra EventID 1 (process create) trong khoảng thời gian này 

![image.png](<images/image 2.png>)

![image.png](<images/image 3.png>)

- User mở **world_clock_setup.exe** từ  lúc **14:00:03**
- **world_clock_setup.exe** gọi **cmd.exe** để khởi chạy **MSBuild.exe** (LOLBin thường dùng để biên dịch/thực thi payload .NET hoặc làm tiến trình đích cho Process Injection).
- **world_clock_setup.exe** dùng **rundll32.exe** nạp file DLL độc hại, tiến trình này bắt đầu nhận lệnh do thám. Vậy ta xác nhận được attacker đã xâm nhập vào hệ thống thành công

## Persistence

![image.png](<images/image 4.png>)

Tiếp đến attacker thực hiện một loạt hành động nhằm recon hệ thống ngoài ra còn tạo một tài khoản với username = SvcAdmin và password = Qwerty12345! và add vào các group có đặc quyền cao nhằm duy trì truy cập trong hệ thống

![image.png](<images/image 5.png>)

Attacker còn tạo một tạo một tác vụ lập lịch để chạy file dll đọc hại mỗi khi người dùng đăng nhập đồng thời thực thi tiêm mã vào một tiến trình hợp lệ explorer.exe để tránh bị phát hiện

![image.png](<images/image 6.png>)

![image.png](<images/image 7.png>)

Tiếp đến attacker tắt chế độ bảo vệ theo thời gian thực (Real-time Protection) của Windows Defender để thực hiện stage tiếp theo

## Credential access

![image.png](<images/image 8.png>)

Tiếp tục điều tra tôi phát hiện vào lúc **2025-12-02 14:45** tiến trình rundll32 đã truy cập vào bộ nhớ của lsass.exe đây là một hành động bất thường nhằm đánh cắp mật khẩu, NTLM hash hoặc Kerberos ticket. 

## Lateral Movement and discovery

![image.png](<images/image 9.png>)

Vào **2025-12-02 15:23:47** từ địa chỉ ip của của máy bị xâm nhập đã tiến hành đăng nhập vài DC với tên đăng nhập là **maurelius**

![image.png](<images/image 10.png>)

Ở đây có 3 dấu hiệu đặc trưng của kỹ thuật tạo **Remote Service:**

- Tiến trình bình thường chạy cục bộ sẽ có đường dẫn `C:\Windows\...`.Việc nó chạy trực tiếp từ đường dẫn mạng `\\DC01.corp.local\ADMIN$\...` là dấu hiệu của các công cụ di chuyển ngang qua SMB + Service Control Manager (như **PsExec**, **Impacket**, hoặc **Cobalt Strike)**
- Tên file ngẫu nhiên 7 ký tự hex đây là mẫu đặt tên mặc định của **Cobalt Strike** khi tạo Service tạm để thực thi payload từ xa.
- Kẻ tấn công kết nối sang DC bằng tài khoản `maurelius`, nhưng tiến trình con trên DC lại chạy dưới quyền `NT AUTHORITY\SYSTEM`Cách đơn giản và phổ biến nhất để thực thi mã từ xa dưới quyền `SYSTEM` chính là tạo một **Windows Service**

![image.png](<images/image 11.png>)

![image.png](<images/image 12.png>)

Sau khi xác minh lại bằng việc điều tra event id 7045 đã chứng minh cho giả thuyết trên là đúng

![image.png](<images/image 13.png>)

![image.png](<images/image 14.png>)

Sau đó attacker sử dụng SharpHound và ADfind để recon môi trường AD

![image.png](<images/image 15.png>)

tiếp đến attacker tạo 1 WMI event chạy 1 file dll độc hại mỗi 60s dưới tên một tiến trình hợp lệ để duy trì sự tồn tại 

## Collection and exfiltration

![image.png](<images/image 16.png>)

Di chuyển ngang sang FS01 

- \\FS01.corp.local\ADMIN$\7ab3ee3.exe tạo ra tiến trình C:\Windows\System32\rundll32.exe. Dùng đúng kỹ thuật Remote Service giống hệt lúc nhảy sang DC01.
- **Trinh sát dữ liệu (Discovery — T1083):**
• cmd.exe /C dir C:\Shares /s (gọi từ rundll32.exe): Liệt kê toàn bộ cây thư mục và file bên trong C:\Shares.
- **Gom và nén dữ liệu nhạy cảm (Collection — T1560.001):**
• Nén toàn bộ dữ liệu 5 phòng ban quan trọng vào file C:\Users\Public\npoived.zip để chuẩn bị cho bước exfiltration.
- **Làm giả mốc thời gian (Defense Evasion — T1070.006):**
• Chạy lệnh PowerShell chỉnh sửa cả 3 thuộc tính CreationTime, LastWriteTime và LastAccessTime của file C:\Users\Public\npoived.zip thành 2036-01-01T00:00:00.
- **Exfiltration**
sao chép trực tiếp file nén dữ liệu nhạy cảm C:\Users\Public\npoived.zip ra thư mục chia sẻ  bên ngoài tại \\3.120.129.182\share\

## Impact

![image.png](<images/image 17.png>)

Attacker drop một ransomware để tiến hành mã hóa dữ liệu để biết được thông tin này tôi tiến hành tra cứu hash của file thực thi trên virustotal

![image.png](<images/image 18.png>)
# Windows Threat Detection - Chi tiết Event Codes

Tài liệu này được viết lại từ file ghi chú gốc `Windows Threat Detection 2c3d1112b06780c18594dd662b95d0ed.md` và các ảnh minh họa đi kèm. Mục tiêu là giúp tra cứu nhanh từng Event ID thường dùng khi điều tra đăng nhập, quản lý tài khoản, tiến trình, service, WMI persistence, file, registry, network và Active Directory.

> Lưu ý: một Event ID đơn lẻ hiếm khi đủ để kết luận độc hại. Khi điều tra, hãy ghép chuỗi theo thời gian, tài khoản, máy nguồn, máy đích, tiến trình cha/con, Logon ID, Process GUID và địa chỉ IP.

## Mục lục

- [Security Log: Authentication](#security-log-authentication)
- [Security Log: User Management](#security-log-user-management)
- [Security Log: Process Monitoring](#security-log-process-monitoring)
- [Security Log: Service, Share và Network](#security-log-service-share-và-network)
- [Sysmon: Process Monitoring](#sysmon-process-monitoring)
- [Sysmon: Files, Registry và Network](#sysmon-files-registry-và-network)
- [Sysmon: WMI Persistence](#sysmon-wmi-persistence)
- [Active Directory và Kerberos](#active-directory-và-kerberos)
- [Quy trình điều tra gợi ý](#quy-trình-điều-tra-gợi-ý)

## Security Log: Authentication

![Security Log Authentication Overview](image.png)

![RDP Brute Force and RDP Login Analysis](image%201.png)

Nhóm sự kiện xác thực dùng để trả lời các câu hỏi: ai đăng nhập, đăng nhập từ đâu, bằng kiểu nào, thành công hay thất bại, và sau khi đăng nhập thì tài khoản đó làm gì.

### Event ID 4624 - Successful Logon

**Ý nghĩa:** ghi nhận một phiên đăng nhập thành công trên Windows.

**Dùng để phát hiện:**

- Đăng nhập RDP thành công sau một chuỗi brute force.
- Đăng nhập bằng tài khoản quản trị ngoài giờ làm việc.
- Lateral movement qua SMB, WinRM, RDP hoặc scheduled task.
- Tài khoản dịch vụ bị lạm dụng để truy cập máy khác.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Tài khoản hoặc tiến trình tạo ra sự kiện. Không phải lúc nào cũng là người đăng nhập thật. |
| `New Logon` | Tài khoản đã đăng nhập thành công. Đây thường là phần quan trọng nhất. |
| `Logon ID` | Mã định danh phiên đăng nhập, dùng để nối với các event khác trên cùng máy. |
| `Logon Type` | Kiểu đăng nhập, ví dụ interactive, network, RDP hoặc service. |
| `Source Network Address` | IP nguồn. Hữu ích hơn hostname khi điều tra truy cập từ xa. |
| `Workstation Name` | Tên máy nguồn, nhưng có thể thiếu hoặc không đáng tin bằng IP. |

**Logon Type hay gặp:**

| Logon Type | Ý nghĩa | Cách diễn giải khi điều tra |
|---|---|---|
| `2` | Interactive | Người dùng đăng nhập trực tiếp tại console hoặc phiên local. |
| `3` | Network | Truy cập qua mạng, thường gặp với SMB, chia sẻ file, remote service. |
| `4` | Batch | Batch job hoặc scheduled task. |
| `5` | Service | Service khởi chạy bằng tài khoản cụ thể. |
| `7` | Unlock | Mở khóa phiên làm việc. |
| `10` | RemoteInteractive | RDP hoặc Terminal Services. |
| `11` | CachedInteractive | Đăng nhập bằng credential cache khi domain controller không sẵn sàng. |

**Dấu hiệu đáng ngờ:**

- `Logon Type 10` từ IP lạ hoặc quốc gia lạ.
- `Logon Type 3` tới nhiều máy trong thời gian ngắn.
- Tài khoản thường dùng giờ hành chính nhưng đăng nhập ban đêm.
- `New Logon` là tài khoản admin nhưng `Source Network Address` không thuộc dải quản trị.
- 4624 xuất hiện ngay sau nhiều 4625 từ cùng IP hoặc cùng username.

**Cách điều tra nhanh:**

1. Lọc `Event ID = 4624`.
2. Kiểm tra `New Logon`, `Logon Type`, `Source Network Address`, `Logon ID`.
3. Nếu là RDP, ưu tiên `Logon Type 10`.
4. Nếu bật NLA, có thể thấy một 4624 `Logon Type 3` trước 4624 `Logon Type 10`.
5. Dùng `Logon ID` để tìm các hành động tiếp theo như tạo process, truy cập share, đổi mật khẩu, hoặc cài service.

### Event ID 4625 - Failed Logon

**Ý nghĩa:** ghi nhận một lần đăng nhập thất bại.

**Dùng để phát hiện:**

- Brute force RDP.
- Password spraying.
- Tài khoản bị đoán mật khẩu.
- Kẻ tấn công thử username phổ biến như `admin`, `administrator`, `helpdesk`, `cctv`.
- Dịch vụ hoặc script dùng mật khẩu cũ.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Account For Which Logon Failed` | Username bị thử đăng nhập. |
| `Failure Information` | Lý do thất bại, ví dụ sai mật khẩu hoặc tài khoản không tồn tại. |
| `Logon Type` | Kiểu đăng nhập bị thử. `3` và `10` rất quan trọng khi phân tích RDP/network. |
| `Source Network Address` | IP nguồn tạo ra đăng nhập lỗi. |
| `Workstation Name` | Tên máy nguồn nếu có. |

**Dấu hiệu đáng ngờ:**

- Nhiều 4625 từ cùng IP tới nhiều username.
- Nhiều 4625 từ nhiều IP tới cùng một username.
- 4625 nhắm vào tài khoản quản trị hoặc tài khoản dịch vụ.
- Tên máy trạm không theo mẫu công ty, ví dụ `kali` thay vì `THM-PC-06`.
- Sau nhiều 4625 có 4624 thành công từ cùng IP.

**Cách điều tra RDP brute force:**

1. Lọc `Event ID = 4625`.
2. Lọc thêm `Logon Type = 3` và `Logon Type = 10`.
3. Nhóm theo `Source Network Address`, `TargetUserName`, `Workstation Name`.
4. Tìm các username bị thử nhiều lần.
5. Kiểm tra xem IP đó có tạo 4624 thành công sau đó không.

### Event ID 4768 - Kerberos Authentication Ticket Requested

**Ý nghĩa:** ghi nhận yêu cầu Kerberos Authentication Service, thường gọi là AS-REQ/AS-REP. Đây là bước đầu khi tài khoản xin Ticket Granting Ticket từ domain controller.

**Dùng để phát hiện:**

- Kerberos pre-authentication failure.
- Password spraying trong môi trường domain.
- AS-REP roasting khi tài khoản không yêu cầu pre-authentication.
- Hoạt động xác thực bất thường tới domain controller.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Account Name` | Tài khoản xin TGT. |
| `Client Address` | IP máy yêu cầu xác thực. |
| `Pre-Authentication Type` | Cho biết cơ chế pre-auth. Giá trị bất thường có thể đáng chú ý. |
| `Ticket Encryption Type` | Kiểu mã hóa ticket. |
| `Failure Code` | Lý do thất bại nếu yêu cầu không thành công. |

**Dấu hiệu đáng ngờ:**

- Nhiều 4768 thất bại từ cùng IP với nhiều tài khoản khác nhau.
- 4768 cho tài khoản không yêu cầu pre-authentication.
- Yêu cầu xác thực từ máy không phải domain-joined hoặc subnet lạ.

### Event ID 4769 - Kerberos Service Ticket Requested

**Ý nghĩa:** ghi nhận yêu cầu Kerberos Service Ticket, thường gọi là TGS-REQ. Sự kiện này cho biết tài khoản nào yêu cầu truy cập dịch vụ nào.

**Dùng để phát hiện:**

- Kerberoasting.
- Lateral movement tới service như CIFS, HOST, MSSQLSvc, HTTP.
- Tài khoản user thường yêu cầu nhiều service ticket bất thường.
- Service account dùng encryption yếu.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Account Name` | Tài khoản yêu cầu service ticket. |
| `Service Name` | Dịch vụ được yêu cầu, ví dụ `cifs/server`, `MSSQLSvc/...`. |
| `Client Address` | IP máy yêu cầu. |
| `Ticket Encryption Type` | Kiểu mã hóa, quan trọng khi săn Kerberoasting. |
| `Status` | Kết quả yêu cầu ticket. |

**Dấu hiệu đáng ngờ:**

- Một user thường yêu cầu nhiều service ticket trong thời gian ngắn.
- Yêu cầu tới nhiều SPN không liên quan công việc.
- `Ticket Encryption Type` dùng RC4 hoặc kiểu mã hóa yếu trong môi trường đã chuẩn hóa AES.
- 4769 xuất hiện sau 4624 từ máy nghi bị compromise.

## Security Log: User Management

![Security Log User Management](image%202.png)

Nhóm sự kiện quản lý người dùng giúp lần theo toàn bộ vòng đời tài khoản: tạo, kích hoạt, chỉnh sửa, đổi mật khẩu, vô hiệu hóa, xóa, thêm nhóm và xóa khỏi nhóm.

### Event ID 4720 - User Account Created

**Ý nghĩa:** một tài khoản người dùng mới đã được tạo.

**Dùng để phát hiện:**

- Kẻ tấn công tạo tài khoản backdoor.
- Tài khoản local admin mới xuất hiện trên máy bị xâm nhập.
- Tài khoản domain được tạo ngoài quy trình cấp quyền.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Ai tạo tài khoản. |
| `New Account` | Tài khoản mới được tạo. |
| `Account Name` | Tên tài khoản mới. |
| `Logon ID` | Dùng nối với phiên đăng nhập trước đó của người tạo. |

**Dấu hiệu đáng ngờ:**

- Tài khoản mới có tên giống hệ thống, ví dụ `svc_sysrestore`, `backup_admin`, `support$`.
- Tài khoản tạo ngoài giờ làm việc.
- Người tạo tài khoản không thuộc nhóm quản trị hợp lệ.
- Ngay sau 4720 có 4722 hoặc 4732 thêm vào nhóm quyền cao.

### Event ID 4722 - User Account Enabled

**Ý nghĩa:** một tài khoản người dùng đã được kích hoạt.

**Dùng để phát hiện:**

- Kích hoạt lại tài khoản cũ để tránh tạo tài khoản mới gây chú ý.
- Tài khoản bị vô hiệu hóa trước đó được bật lại trái quy trình.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Ai bật tài khoản. |
| `Target Account` | Tài khoản được kích hoạt. |
| `Logon ID` | Liên kết với phiên đăng nhập của người thực hiện. |

**Dấu hiệu đáng ngờ:**

- Tài khoản cũ, không còn dùng, bất ngờ được bật lại.
- Tài khoản được bật rồi đăng nhập ngay sau đó.
- Tài khoản được bật bởi user không thuộc nhóm quản trị phù hợp.

### Event ID 4738 - User Account Changed

**Ý nghĩa:** thuộc tính tài khoản người dùng đã bị thay đổi.

**Dùng để phát hiện:**

- Thay đổi thuộc tính tài khoản để duy trì truy cập.
- Chỉnh cờ mật khẩu, thời hạn hết hạn, UPN, mô tả hoặc nhóm liên quan.
- Thay đổi tài khoản dịch vụ hoặc tài khoản đặc quyền.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Ai thực hiện thay đổi. |
| `Target Account` | Tài khoản bị thay đổi. |
| `Changed Attributes` | Thuộc tính trước và sau khi thay đổi. |

**Dấu hiệu đáng ngờ:**

- `Password Never Expires` bị bật cho tài khoản không phù hợp.
- `User Account Control` thay đổi bất thường.
- Tài khoản thường bị đổi mô tả hoặc UPN để ngụy trang.

### Event ID 4723 - Attempt to Change Password

**Ý nghĩa:** người dùng cố đổi mật khẩu của chính họ.

**Dùng để phát hiện:**

- Tài khoản bị takeover rồi kẻ tấn công đổi mật khẩu.
- Người dùng hợp lệ đổi mật khẩu sau cảnh báo bảo mật.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Ai yêu cầu đổi mật khẩu. |
| `Target Account` | Tài khoản bị đổi mật khẩu, thường là chính tài khoản đó. |
| `Status` | Thành công hoặc thất bại tùy log chi tiết. |

**Dấu hiệu đáng ngờ:**

- Đổi mật khẩu ngay sau đăng nhập từ IP lạ.
- Nhiều lần đổi mật khẩu thất bại.
- Đổi mật khẩu rồi xuất hiện đăng nhập từ nhiều máy khác nhau.

### Event ID 4724 - Attempt to Reset Password

**Ý nghĩa:** một tài khoản cố đặt lại mật khẩu cho tài khoản khác.

**Dùng để phát hiện:**

- Admin hoặc helpdesk bị lạm dụng để reset mật khẩu.
- Kẻ tấn công reset mật khẩu tài khoản mục tiêu để chiếm quyền.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Tài khoản thực hiện reset. |
| `Target Account` | Tài khoản bị đặt lại mật khẩu. |
| `Logon ID` | Nối với phiên đăng nhập của người thực hiện. |

**Dấu hiệu đáng ngờ:**

- Reset mật khẩu cho tài khoản đặc quyền.
- Reset diễn ra ngoài quy trình hỗ trợ.
- Sau reset có 4624 thành công vào tài khoản mục tiêu.

### Event ID 4725 - User Account Disabled

**Ý nghĩa:** một tài khoản người dùng đã bị vô hiệu hóa.

**Dùng để phát hiện:**

- SOC hoặc admin phản ứng với sự cố.
- Kẻ tấn công vô hiệu hóa tài khoản phòng thủ hoặc tài khoản quản trị khác.
- Dấu hiệu che giấu sau khi đã tạo tài khoản backdoor thay thế.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Ai vô hiệu hóa tài khoản. |
| `Target Account` | Tài khoản bị vô hiệu hóa. |

**Dấu hiệu đáng ngờ:**

- Tài khoản bảo mật, backup, EDR hoặc admin bị vô hiệu hóa.
- Tài khoản bị disable ngay sau khi có hoạt động đăng nhập lạ.

### Event ID 4726 - User Account Deleted

**Ý nghĩa:** một tài khoản người dùng đã bị xóa.

**Dùng để phát hiện:**

- Xóa tài khoản backdoor sau khi hoàn tất hành động.
- Xóa tài khoản để phá vỡ hoạt động vận hành.
- Xóa tài khoản nhằm làm khó điều tra.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Ai xóa tài khoản. |
| `Target Account` | Tài khoản bị xóa. |
| `Logon ID` | Nối với phiên đăng nhập của người xóa. |

**Dấu hiệu đáng ngờ:**

- 4720 tạo tài khoản, 4732 thêm nhóm, sau đó 4726 xóa tài khoản trong cùng ngày.
- Xóa tài khoản service hoặc tài khoản domain quan trọng.

### Event ID 4732 - Member Added to Security-Enabled Local Group

**Ý nghĩa:** một thành viên được thêm vào nhóm bảo mật cục bộ.

**Dùng để phát hiện:**

- Tài khoản bị thêm vào `Administrators`, `Remote Desktop Users`, `Backup Operators`.
- Leo thang đặc quyền sau khi tạo tài khoản mới.
- Persistence bằng cách thêm user vào nhóm quyền cao.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Ai thêm thành viên. |
| `Member` | Tài khoản được thêm. |
| `Group Name` | Nhóm được thêm vào. |

**Dấu hiệu đáng ngờ:**

- Thành viên mới được thêm vào nhóm `Administrators`.
- Tài khoản vừa được tạo ở 4720 được thêm nhóm ở 4732.
- Thao tác xảy ra trên máy chủ quan trọng hoặc domain controller.

### Event ID 4733 - Member Removed from Security-Enabled Local Group

**Ý nghĩa:** một thành viên bị xóa khỏi nhóm bảo mật cục bộ.

**Dùng để phát hiện:**

- Kẻ tấn công loại bỏ admin hoặc nhóm phòng thủ.
- Dọn dấu vết sau khi dùng tài khoản tạm.
- Thay đổi quyền không đúng quy trình.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Ai xóa thành viên. |
| `Member` | Tài khoản bị xóa khỏi nhóm. |
| `Group Name` | Nhóm bị thay đổi. |

**Dấu hiệu đáng ngờ:**

- Tài khoản SOC, helpdesk hoặc admin bị xóa khỏi nhóm quyền cao.
- 4733 xuất hiện ngay sau 4732, có thể là thao tác dọn dấu vết.

## Security Log: Process Monitoring

### Event ID 4688 - Process Creation

![Security Log 4688 and Sysmon 1 Comparison](image%203.png)

**Ý nghĩa:** ghi nhận khi một tiến trình mới được tạo. Đây là log native của Windows Security, nhưng cần bật policy audit phù hợp và nên bật thêm command line process auditing để có dữ liệu đầy đủ.

**Dùng để phát hiện:**

- Thực thi command đáng ngờ như `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`.
- Lateral movement tạo process từ xa.
- Script download payload.
- Process chain bất thường từ Office, browser, service hoặc scheduled task.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Creator Subject` | Tài khoản tạo process. |
| `New Process Name` | File thực thi được khởi chạy. |
| `Process Command Line` | Dòng lệnh, rất quan trọng nếu đã bật audit command line. |
| `Creator Process Name` | Process cha. |
| `Token Elevation Type` | Gợi ý process có quyền elevated hay không. |
| `Logon ID` | Nối với 4624 để biết phiên đăng nhập tạo process. |

**Dấu hiệu đáng ngờ:**

- `powershell.exe` chạy với `-enc`, `-nop`, `-w hidden`.
- Office hoặc browser spawn `cmd.exe`/`powershell.exe`.
- `rundll32.exe`, `regsvr32.exe`, `mshta.exe` chạy từ thư mục user hoặc temp.
- Command line tải file từ Internet hoặc gọi IP trực tiếp.

**Hạn chế:**

- Mặc định có thể chưa bật.
- Không giàu ngữ cảnh bằng Sysmon Event ID 1.
- Có thể thiếu hash, signature, Process GUID và thông tin parent chi tiết.

## Security Log: Service, Share và Network

### Event ID 4697 - Service Installed

**Ý nghĩa:** một service mới được cài đặt, được ghi trong Security log nếu audit phù hợp được bật.

**Dùng để phát hiện:**

- Persistence bằng Windows service.
- PsExec hoặc công cụ remote execution tạo service tạm.
- Cài malware dưới dạng service.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Service Name` | Tên service mới. |
| `Service File Name` | Đường dẫn binary hoặc command của service. |
| `Service Account` | Tài khoản service chạy dưới quyền nào. |
| `Subject` | Ai tạo service. |

**Dấu hiệu đáng ngờ:**

- Service path nằm trong `C:\Users\`, `C:\ProgramData\`, `C:\Windows\Temp\`.
- Tên service giống chuỗi ngẫu nhiên.
- Service chạy bằng tài khoản đặc quyền.
- 4697 xuất hiện sau 4624 Type 3 từ máy lạ.

### Event ID 7045 - Service Installed

**Ý nghĩa:** một service mới được cài đặt, được ghi trong System log. Đây là event rất quan trọng khi phát hiện persistence hoặc remote execution.

**Dùng để phát hiện:**

- Cài service mới trái phép.
- Remote execution bằng PsExec, Impacket, Cobalt Strike hoặc công cụ quản trị bị lạm dụng.
- Malware tạo service để tự khởi động.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Service Name` | Tên service. |
| `ImagePath` hoặc `Service File Name` | Binary hoặc command service chạy. |
| `Service Type` | Kiểu service. |
| `Start Type` | Tự động, thủ công hoặc disabled. |
| `Account Name` | Tài khoản chạy service. |

**Dấu hiệu đáng ngờ:**

- Service chạy từ thư mục user, temp hoặc share mạng.
- Tên service ngắn, ngẫu nhiên hoặc giả dạng Windows.
- `ImagePath` chứa `cmd.exe /c`, `powershell`, script hoặc encoded command.
- 7045 xảy ra gần thời điểm có 4624 Type 3 hoặc 4688 đáng ngờ.

### Event ID 5140 - Network Share Accessed

**Ý nghĩa:** một network share được truy cập.

**Dùng để phát hiện:**

- Truy cập share quản trị như `ADMIN$`, `C$`, `IPC$`.
- Lateral movement qua SMB.
- Truy cập dữ liệu nhạy cảm trên file server.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Subject` | Tài khoản truy cập share. |
| `Share Name` | Share được truy cập. |
| `Client Address` | IP nguồn. |
| `Accesses` | Loại truy cập được yêu cầu. |

**Dấu hiệu đáng ngờ:**

- Truy cập `ADMIN$` hoặc `C$` từ máy không thuộc nhóm quản trị.
- Một tài khoản truy cập nhiều share trong thời gian ngắn.
- Truy cập share sau đăng nhập 4624 Type 3 từ IP lạ.

### Event ID 5145 - Detailed File Share Access

**Ý nghĩa:** ghi chi tiết quyền truy cập vào file hoặc thư mục qua network share.

**Dùng để phát hiện:**

- Đọc, ghi, tạo hoặc xóa file qua SMB.
- Copy payload tới `ADMIN$`.
- Exfiltration từ file share.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Share Name` | Share bị truy cập. |
| `Relative Target Name` | File hoặc thư mục cụ thể. |
| `Accesses` | Quyền truy cập như ReadData, WriteData, Delete. |
| `Client Address` | IP nguồn. |

**Dấu hiệu đáng ngờ:**

- Ghi file `.exe`, `.dll`, `.ps1`, `.bat` vào share quản trị.
- Truy cập hàng loạt file nhạy cảm.
- 5145 đi kèm 7045, thường là copy binary rồi tạo service.

### Event ID 5156 - Windows Filtering Platform Allowed Connection

**Ý nghĩa:** Windows Filtering Platform cho phép một kết nối mạng. Có thể xem đây là nguồn thay thế hoặc bổ sung cho Sysmon Event ID 3 khi cần điều tra network connection từ Security log.

**Dùng để phát hiện:**

- Kết nối outbound tới IP hoặc domain đáng ngờ.
- Process nội bộ mở kết nối lạ.
- Dấu vết C2 hoặc tải payload.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Application Name` | Process tạo kết nối. |
| `Source Address` | IP nguồn. |
| `Source Port` | Port nguồn. |
| `Destination Address` | IP đích. |
| `Destination Port` | Port đích. |
| `Protocol` | Giao thức, thường TCP hoặc UDP. |

**Dấu hiệu đáng ngờ:**

- `powershell.exe`, `rundll32.exe`, `regsvr32.exe` kết nối Internet.
- Kết nối tới IP hiếm gặp, ASN lạ hoặc port bất thường.
- Kết nối xảy ra ngay sau Sysmon 11 tạo file hoặc Sysmon 1 tạo process đáng ngờ.

## Sysmon: Process Monitoring

### Sysmon Event ID 1 - Process Creation

**Ý nghĩa:** ghi nhận tiến trình mới được tạo với nhiều trường giàu ngữ cảnh hơn 4688, như hash, signature, Process GUID, parent process và command line.

**Dùng để phát hiện:**

- Execution bằng LOLBins.
- Process chain độc hại.
- Payload chạy từ thư mục user, temp, downloads.
- Parent-child relationship bất thường.
- Kết nối các event Sysmon khác qua `ProcessGuid`.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `UtcTime` | Thời điểm tạo process theo UTC. |
| `ProcessGuid` | ID ổn định để nối với các event Sysmon khác. |
| `ProcessId` | PID, có thể tái sử dụng nên không nên dùng một mình. |
| `Image` | Đường dẫn executable. |
| `CommandLine` | Dòng lệnh đầy đủ. |
| `CurrentDirectory` | Thư mục làm việc. |
| `User` | Tài khoản chạy process. |
| `Hashes` | Hash file để tra cứu IOC. |
| `ParentImage` | Process cha. |
| `ParentCommandLine` | Dòng lệnh process cha. |

**Dấu hiệu đáng ngờ:**

- Binary hệ thống chạy từ vị trí không chuẩn.
- `ParentImage` là Office, browser, archive tool nhưng process con là shell hoặc script engine.
- Command line chứa URL, IP, base64, encoded command hoặc obfuscation.
- `Image` nằm trong `Downloads`, `Temp`, `AppData`, `ProgramData`.

## Sysmon: Files, Registry và Network

![Sysmon Files Registry Network](image%204.png)

### Sysmon Event ID 3 - Network Connection

**Ý nghĩa:** ghi nhận kết nối mạng do process tạo ra, nếu cấu hình Sysmon bật network connection logging.

**Dùng để phát hiện:**

- Kết nối C2.
- Tải payload từ Internet.
- Process không nên ra mạng nhưng lại kết nối outbound.
- Lateral movement tới máy nội bộ.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Image` | Process tạo kết nối. |
| `User` | Tài khoản chạy process. |
| `SourceIp` / `SourcePort` | Nguồn kết nối. |
| `DestinationIp` / `DestinationPort` | Đích kết nối. |
| `Protocol` | TCP hoặc UDP. |
| `Initiated` | Cho biết process chủ động tạo kết nối hay không. |

**Dấu hiệu đáng ngờ:**

- `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe` kết nối Internet.
- Kết nối tới IP public ngay sau khi file lạ được tạo.
- Port bất thường hoặc kết nối tới nhiều IP trong thời gian ngắn.

### Sysmon Event ID 11 - File Created

**Ý nghĩa:** ghi nhận file mới được tạo theo rule Sysmon.

**Dùng để phát hiện:**

- Malware drop file xuống máy.
- Payload được tải vào `Downloads`, `Temp`, `AppData`, `ProgramData`.
- File thực thi hoặc script xuất hiện trên máy chủ.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Image` | Process tạo file. |
| `TargetFilename` | File được tạo. |
| `User` | Tài khoản tạo file. |
| `ProcessGuid` | Nối với Sysmon 1 của process tạo file. |

**Dấu hiệu đáng ngờ:**

- File `.exe`, `.dll`, `.ps1`, `.vbs`, `.bat`, `.lnk` trong thư mục user hoặc temp.
- Browser hoặc Office tạo file thực thi.
- File được tạo rồi ngay lập tức được chạy ở Sysmon 1.

### Sysmon Event ID 13 - Registry Value Set

**Ý nghĩa:** ghi nhận một giá trị registry được tạo hoặc thay đổi.

**Dùng để phát hiện:**

- Persistence qua Run key.
- Thay đổi cấu hình bảo mật hoặc startup.
- Malware ghi cấu hình vào registry.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Image` | Process sửa registry. |
| `TargetObject` | Khóa hoặc value registry bị sửa. |
| `Details` | Giá trị mới được ghi. |
| `User` | Tài khoản thực hiện. |

**Dấu hiệu đáng ngờ:**

- Ghi vào `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- Ghi vào `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`.
- `Details` trỏ tới file trong `Temp`, `Downloads`, `AppData`.
- Script engine hoặc LOLBin thay đổi registry startup.

### Sysmon Event ID 15 - FileCreateStreamHash

**Ý nghĩa:** ghi nhận khi file được tạo với Alternate Data Stream và Sysmon tính hash của stream đó.

**Dùng để phát hiện:**

- File tải từ Internet có Zone.Identifier.
- Lạm dụng Alternate Data Stream để ẩn dữ liệu.
- Payload hoặc script bị giấu trong stream phụ của NTFS.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `TargetFilename` | File và stream được tạo. |
| `Hash` | Hash của stream. |
| `Image` | Process tạo stream. |
| `User` | Tài khoản thực hiện. |

**Dấu hiệu đáng ngờ:**

- Stream lạ ngoài `Zone.Identifier`.
- File thực thi có ADS bất thường.
- Dữ liệu ẩn trong `filename:streamname`.

### Sysmon Event ID 22 - DNS Query

**Ý nghĩa:** ghi nhận truy vấn DNS do process tạo ra, nếu cấu hình Sysmon bật DNS query logging.

**Dùng để phát hiện:**

- Malware resolve domain C2.
- Domain generated algorithm hoặc domain hiếm.
- Process nội bộ truy vấn domain đáng ngờ.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Image` | Process thực hiện DNS query. |
| `QueryName` | Domain được truy vấn. |
| `QueryResults` | IP trả về. |
| `QueryStatus` | Trạng thái truy vấn. |
| `User` | Tài khoản chạy process. |

**Dấu hiệu đáng ngờ:**

- Domain mới, dài, ngẫu nhiên hoặc giống DGA.
- `QueryName` trỏ tới hạ tầng không liên quan doanh nghiệp.
- DNS query xảy ra ngay trước Sysmon 3 kết nối tới IP trả về.

## Sysmon: WMI Persistence

### Sysmon Event ID 19 - WMI Event Filter

**Ý nghĩa:** ghi nhận WMI event filter được tạo. WMI filter định nghĩa điều kiện kích hoạt, ví dụ khi hệ thống khởi động hoặc khi một điều kiện WMI xảy ra.

**Dùng để phát hiện:**

- Persistence bằng WMI permanent event subscription.
- Malware tạo điều kiện kích hoạt tự động.
- Script hoặc command được cấu hình chạy theo sự kiện hệ thống.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Name` | Tên filter. |
| `Query` | Điều kiện WMI dùng để kích hoạt. |
| `EventNamespace` | Namespace WMI. |
| `User` | Tài khoản tạo filter. |

**Dấu hiệu đáng ngờ:**

- Query dùng `__InstanceModificationEvent` hoặc trigger theo thời gian.
- Tên filter giả dạng Windows hoặc chuỗi ngẫu nhiên.
- Filter được tạo cùng thời điểm với Sysmon 20.

### Sysmon Event ID 20 - WMI Event Consumer

**Ý nghĩa:** ghi nhận WMI event consumer được tạo. Consumer định nghĩa hành động sẽ chạy khi filter được kích hoạt.

**Dùng để phát hiện:**

- Persistence bằng command line hoặc script chạy qua WMI.
- Malware cấu hình `CommandLineEventConsumer`.
- Cơ chế tự khởi chạy sau reboot hoặc theo lịch ngầm.

**Trường cần chú ý:**

| Trường | Cách đọc |
|---|---|
| `Name` | Tên consumer. |
| `Type` | Loại consumer, ví dụ `CommandLineEventConsumer`. |
| `Destination` hoặc `CommandLineTemplate` | Lệnh sẽ chạy. |
| `User` | Tài khoản tạo consumer. |

**Dấu hiệu đáng ngờ:**

- Consumer chạy `powershell`, `cmd`, `wscript`, `mshta`.
- Command trỏ tới file trong `Temp`, `AppData`, `ProgramData`.
- Event 19, 20 và binding WMI xuất hiện gần nhau.

## Active Directory và Kerberos

Trong môi trường domain, hãy ưu tiên ghép các sự kiện Kerberos với sự kiện đăng nhập và quản lý tài khoản:

- `4768`: tài khoản xin TGT từ domain controller.
- `4769`: tài khoản xin service ticket để truy cập service.
- `4624`: đăng nhập thành công trên máy đích.
- `4625`: đăng nhập thất bại trên máy đích.
- `4720`, `4722`, `4738`, `4732`: thay đổi vòng đời và đặc quyền tài khoản.

**Chuỗi điều tra Kerberoasting gợi ý:**

1. Tìm nhiều `4769` từ cùng một user trong thời gian ngắn.
2. Kiểm tra `Service Name` có nhiều SPN khác nhau không.
3. Kiểm tra `Ticket Encryption Type`, đặc biệt nếu xuất hiện kiểu mã hóa yếu.
4. Đối chiếu `Client Address` với máy người dùng hợp lệ.
5. Tìm 4624 hoặc Sysmon 1 trên máy client cùng thời điểm để biết công cụ nào được chạy.

**Chuỗi điều tra account compromise gợi ý:**

1. Tìm `4625` bất thường trước.
2. Kiểm tra có `4624` thành công từ cùng IP không.
3. Dùng `Logon ID` nối sang `4688` hoặc Sysmon 1.
4. Kiểm tra có thay đổi user/group như `4720`, `4722`, `4724`, `4732` không.
5. Kiểm tra network/share/service như `5140`, `5145`, `7045`.

## Quy trình điều tra gợi ý

### 1. Bắt đầu từ dấu hiệu đăng nhập

- Nếu thấy brute force: bắt đầu với `4625`, nhóm theo IP nguồn và username.
- Nếu thấy đăng nhập lạ: bắt đầu với `4624`, lọc `Logon Type 3` và `10`.
- Nếu nghi domain compromise: kiểm tra thêm `4768` và `4769` trên domain controller.

### 2. Xác định phiên và tài khoản

- Ghi lại `Account Name`, `Domain`, `Logon ID`, `Source Network Address`.
- Đối chiếu thời gian giữa máy nguồn, máy đích và domain controller.
- Không dựa duy nhất vào hostname vì trường này có thể thiếu hoặc không đáng tin.

### 3. Tìm hành động sau đăng nhập

- Process: `4688` hoặc Sysmon `1`.
- Service mới: `7045` hoặc `4697`.
- Share access: `5140`, `5145`.
- File mới: Sysmon `11`.
- Registry persistence: Sysmon `13`.
- Network/DNS: Sysmon `3`, Sysmon `22`, Security `5156`.
- WMI persistence: Sysmon `19`, `20`.

### 4. Ghép chuỗi hành vi

Ví dụ chuỗi thường gặp khi lateral movement bằng service:

1. `4624` với `Logon Type 3` từ IP lạ.
2. `5145` ghi file vào `ADMIN$` hoặc `C$`.
3. `7045` service mới được cài.
4. Sysmon `1` process service chạy payload.
5. Sysmon `3` payload kết nối ra ngoài.

Ví dụ chuỗi thường gặp khi tạo tài khoản backdoor:

1. `4624` đăng nhập bằng tài khoản có quyền.
2. `4720` tạo tài khoản mới.
3. `4722` kích hoạt tài khoản.
4. `4732` thêm tài khoản vào nhóm `Administrators`.
5. `4624` đăng nhập bằng tài khoản mới.

### 5. Kết luận và hành động

- Xác định tài khoản bị ảnh hưởng.
- Xác định máy nguồn, máy đích và thời điểm đầu tiên.
- Thu thập command line, hash, file path, registry key, IP/domain.
- Khóa hoặc reset tài khoản nếu có bằng chứng compromise.
- Cô lập máy nếu thấy payload, persistence hoặc C2.
- Lưu IOC để săn tìm trên toàn hệ thống.

## Bảng tra cứu nhanh

| Event ID | Log Source | Nhóm | Ý nghĩa ngắn |
|---|---|---|---|
| `4624` | Security | Authentication | Đăng nhập thành công. |
| `4625` | Security | Authentication | Đăng nhập thất bại. |
| `4768` | Security/DC | Kerberos | Yêu cầu TGT. |
| `4769` | Security/DC | Kerberos | Yêu cầu service ticket. |
| `4720` | Security | User Management | Tạo tài khoản. |
| `4722` | Security | User Management | Kích hoạt tài khoản. |
| `4738` | Security | User Management | Thay đổi tài khoản. |
| `4723` | Security | User Management | User đổi mật khẩu của chính mình. |
| `4724` | Security | User Management | Reset mật khẩu tài khoản khác. |
| `4725` | Security | User Management | Vô hiệu hóa tài khoản. |
| `4726` | Security | User Management | Xóa tài khoản. |
| `4732` | Security | Group Management | Thêm thành viên vào nhóm local security. |
| `4733` | Security | Group Management | Xóa thành viên khỏi nhóm local security. |
| `4688` | Security | Process | Tạo process. |
| `4697` | Security | Service | Cài service mới. |
| `7045` | System | Service | Cài service mới. |
| `5140` | Security | Share | Truy cập network share. |
| `5145` | Security | Share | Truy cập chi tiết file qua share. |
| `5156` | Security | Network | WFP cho phép kết nối mạng. |
| `1` | Sysmon | Process | Tạo process chi tiết. |
| `3` | Sysmon | Network | Kết nối mạng. |
| `8` | Sysmon | Injection | CreateRemoteThread. |
| `11` | Sysmon | File | Tạo file. |
| `13` | Sysmon | Registry | Set giá trị registry. |
| `15` | Sysmon | File/ADS | Tạo stream và hash ADS. |
| `19` | Sysmon | WMI | Tạo WMI event filter. |
| `20` | Sysmon | WMI | Tạo WMI event consumer. |
| `22` | Sysmon | DNS | Truy vấn DNS. |

## Ghi nhớ ngắn

- `4625` nhiều lần rồi `4624` thành công: nghi brute force thành công.
- `4624 Type 3` cộng `5145` cộng `7045`: nghi remote service execution.
- `4720` cộng `4732`: nghi tạo tài khoản và leo quyền.
- Sysmon `1` là bản giàu thông tin hơn `4688`.
- Sysmon `3` hoặc Security `5156` giúp nhìn network connection.
- Sysmon `11`, `13`, `15`, `19`, `20`, `22` giúp săn persistence và payload.

# SIEM + SOAR Incident Response

Xây dựng hệ thống tự động phát hiện và phản ứng sự cố bảo mật theo mô hình SIEM + SOAR sử dụng **Wazuh** và **Shuffle**. Dự án triển khai 2 kịch bản thực tế: phát hiện tấn công phishing qua malware fileless và phát hiện email phishing qua Gmail, cả hai đều kết thúc bằng phản ứng tự động mà không cần can thiệp thủ công.

---

## Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────┐
│              Windows 10 Agent (DESKTOP-7FF2J6R)          │
│              IP: 192.168.1.13                            │
│              Sysmon + Wazuh Agent v4.7.0                 │
└────────────────────────┬────────────────────────────────┘
                         │ TCP 1514
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Wazuh Manager (Ubuntu)                      │
│              IP: 192.168.1.100                           │
│              Custom rules · Active Response · Syscheck   │
└────────────────────────┬────────────────────────────────┘
                         │ Webhook (JSON alert)
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Shuffle SOAR                                │
│              VirusTotal API · Gmail API · Wazuh API      │
└────────────────────────┬────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        Email Alert           Active Response
        (SOC Analyst)    (netsh block IP on agent)
```

---

## Công nghệ sử dụng

| Thành phần | Vai trò |
|------------|---------|
| **Wazuh 4.7** | SIEM – thu thập log, phát hiện tấn công, kích hoạt Active Response |
| **Sysmon** | Thu thập Windows event log chi tiết (process create, file create, network) |
| **Shuffle** | SOAR – tự động hóa điều tra và phản ứng sự cố |
| **VirusTotal API** | Kiểm tra độ nguy hiểm của URL, IP, domain, file hash |
| **Gmail API** | Trigger kịch bản email phishing, gửi cảnh báo SOC |
| **Windows Defender Firewall** | Thực thi block IP qua lệnh `netsh advfirewall` |

---

## Kịch bản

### KB1 – [Phishing Malware Response](./phishing-malware-response/scenario.md)

Phát hiện và phân tích tấn công PowerShell fileless download malware.

**Luồng xử lý:**
```
PowerShell -ExecutionPolicy Bypass (DownloadFile)
    → Sysmon EventID 1 + 11
    → Wazuh rule 100011 (level 14) + 100003 (level 11)
    → Shuffle: Base64 URL → VT check URL + IP + hash
    → Email cảnh báo SOC (kèm kết quả phân tích)
```

**Kết quả:** URL EICAR phát hiện malicious 11 engines, email cảnh báo gửi trong vòng < 60 giây.

---

### KB2 – [Email Phishing Detection](./phishing-malware-response/Email-Phishing-Detection/scenario.md)

Tự động phân tích email phishing từ Gmail và block IP người gửi.

**Luồng xử lý:**
```
Gmail trigger (poll unread)
    → Extract URL + IP + domain + attachment
    → Parallel: VT check URL (18 engines) + IP + domain (C2) + hash
    → check_any_malicious() = MALICIOUS
    → Wazuh Active Response: netsh block 203.0.113.45
    → Gmail trash email + Email báo cáo SOC
```

**Kết quả:** IP bị block tự động trên Windows Firewall, email phishing bị xóa, báo cáo gửi SOC.

---

## Cấu trúc repo

```
siem-soar-incident-response/
├── phishing-malware-response/
│   ├── Email-Phishing-Detection/
│   │   ├── images/
│   │   └── scenario.md          # KB2: Email phishing workflow
│   ├── Phishing-Malware-Response/
│   │   ├── images/
│   │   └── scenario.md          # KB1: Malware fileless workflow
│   └── shuffle-workflow/
│       ├── Email_Phishing_Detection.json
│       └── Phishing_Malware_Response.json
├── BTL_GSATM_N15-Final.pdf      # Báo cáo đầy đủ
└── README.md
```

---

## Custom Wazuh Rules

| Rule ID | Level | Kịch bản | Mô tả |
|---------|-------|----------|-------|
| 100003 | 11 | KB1 | Sysmon phát hiện file thực thi drop vào Temp/Downloads/AppData |
| 100011 | 14 | KB1 | PowerShell LOLBin/fileless attack (DownloadFile, IEX, bypass) |
| 100040 | 12 | KB1 | Email phishing phát hiện từ Shuffle |
| 100041 | 14 | KB1 | URL độc hại trong email (VT malicious) |
| 100042 | 15 | KB1 | File đính kèm độc hại (VT malicious) |
| 100050 | 14 | KB2 | SOAR Action – xác nhận IP bị block bởi Active Response |

---

## Kết quả đạt được

- Phát hiện và phản ứng tự động trong **< 60 giây** kể từ khi tấn công xảy ra
- Kiểm tra đa nguồn song song: URL + IP + domain + file hash qua VirusTotal
- Block IP tự động trên Windows Defender Firewall không cần can thiệp thủ công
- Gửi báo cáo sự cố đầy đủ đến SOC Analyst qua email
- Xóa email phishing khỏi hộp thư sau khi xử lý
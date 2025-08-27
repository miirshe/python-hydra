# Python Hydra 🐍

A professional and dynamic HTTP authentication brute force tool for penetration testing and security research.

**👨‍💻 Software Engineer | AI, Web & Cybersecurity Enthusiast**  
**Author: Abdikafi Isse Isak (miirshe)**  
**Email: miirshe@gmail.com**

## ⚠️ Legal Disclaimer

**This tool is for educational purposes and authorized security testing only. Always ensure you have explicit permission before testing any system. Unauthorized use may be illegal and could result in legal consequences.**

## 🚀 Features

- **Multi-threaded attacks** for faster execution
- **Configurable success/failure indicators** for accurate detection
- **Session management** with cookies and headers
- **Rate limiting** to avoid detection
- **Comprehensive logging** to file and console
- **JSON configuration files** for easy customization
- **Command-line interface** with multiple options
- **Progress tracking** and statistics
- **Result export** in JSON format
- **Professional error handling** and recovery

## 📋 Requirements

- Python 3.7+
- `requests` library
- `urllib3` library

## 🛠️ Installation

1. **Clone or download** the tool:
```bash
git clone <repository-url>
cd python-hydra
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Make executable** (optional):
```bash
chmod +x python_hydra.py
```

## 📖 Usage

### Basic Usage

```bash
# Simple attack with single username
python python_hydra.py -u admin -p passwords.txt -t https://example.com/login

# Multiple usernames from file
python python_hydra.py -U usernames.txt -P passwords.txt -t https://example.com/login

# Using configuration file
python python_hydra.py -c config.json
```

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-t, --target` | Target URL | `-t https://example.com/login` |
| `-u, --username` | Single username or comma-separated | `-u admin` or `-u admin,user,test` |
| `-U, --usernames` | Username file | `-U users.txt` |
| `-p, --password` | Password file | `-p pass.txt` |
| `-P, --passwords` | Password file (alternative) | `-P passwords.txt` |
| `-c, --config` | Configuration file | `-c config.json` |
| `-o, --output` | Output file for results | `-o results.json` |
| `--delay` | Delay between requests (seconds) | `--delay 1.0` |
| `--threads` | Number of threads | `--threads 10` |
| `--stop-first` | Stop on first successful login | `--stop-first` |
| `--verbose` | Verbose output | `--verbose` |
| `--create-config` | Create sample configuration file | `--create-config` |

### Configuration File

Create a configuration file manually for complex targets. Here's an example structure:

```json
{
  "target": {
    "url": "https://example.com/login",
    "form_data": {
      "username": "",
      "password": "",
      "submit": "Login"
    },
    "success_indicators": [
      "Welcome",
      "Dashboard",
      "Logout"
    ],
    "failure_indicators": [
      "Invalid credentials",
      "Login failed",
      "Username or password is incorrect"
    ]
  },
  "attack": {
    "delay": 0.5,
    "timeout": 30,
    "max_workers": 5,
    "stop_on_first": false
  },
  "headers": {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  },
  "cookies": {
    "session_id": "your_session_id_here"
  }
}
```

## 🔧 Customization

### Success/Failure Indicators

Configure what text indicates successful or failed login attempts:

```json
"success_indicators": [
  "Welcome back",
  "Dashboard",
  "My Account",
  "Logout"
],
"failure_indicators": [
  "Invalid credentials",
  "Login failed",
  "Username or password is incorrect",
  "Access denied"
]
```

### Form Data

Specify the exact form field names and additional data:

```json
"form_data": {
  "username": "",
  "password": "",
  "remember": "1",
  "submit": "Sign In"
}
```

### Headers and Cookies

Customize HTTP headers and cookies for your target:

```json
"headers": {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Accept": "application/json, text/plain, */*",
  "X-Requested-With": "XMLHttpRequest"
},
"cookies": {
  "PHPSESSID": "abc123def456",
  "csrf_token": "xyz789"
}
```

## 📊 Output

The tool provides:

1. **Real-time progress** during execution
2. **Detailed logging** to `python_hydra.log`
3. **JSON results** with timestamps and statistics
4. **Console summary** of successful credentials

### Sample Output

```
[+] SUCCESS: admin:password123 - Success indicator found: Welcome
[+] SUCCESS: user:secret456 - Success indicator found: Dashboard

Brute force attack completed!
Successful attempts: 2
Failed attempts: 998
Total attempts: 1000
```

## 🎯 Examples

### Example 1: Basic WordPress Login

```bash
python python_hydra.py \
  -t https://example.com/wp-login.php \
  -u admin \
  -p common_passwords.txt \
  --delay 1.0 \
  --threads 3
```

### Example 2: Custom Form with Configuration

```bash
# Create config.json manually with your target details
# Then run:
python python_hydra.py -c config.json -U users.txt -P passwords.txt
```

### Example 3: Multiple Usernames, Stop on First Success

```bash
python python_hydra.py \
  -t https://example.com/login \
  -U admin_users.txt \
  -P rockyou.txt \
  --stop-first \
  --threads 10
```

## 🚨 Security Considerations

- **Rate limiting**: Use appropriate delays to avoid triggering security measures
- **Session management**: Some sites require valid session cookies
- **CAPTCHA handling**: This tool doesn't handle CAPTCHAs automatically
- **IP blocking**: Be aware of potential IP blocking mechanisms
- **Legal compliance**: Always ensure you have authorization

## 🔍 Troubleshooting

### Common Issues

1. **"No clear success/failure indicators"**
   - Adjust your success/failure indicators in the config
   - Check the response manually to identify patterns

2. **"Request failed" errors**
   - Verify the target URL is accessible
   - Check if you need valid session cookies
   - Ensure proper form field names

3. **Slow performance**
   - Increase thread count (but be careful with rate limiting)
   - Reduce delay between requests
   - Check network connectivity

### Debug Mode

Use verbose output to see detailed information:

```bash
python python_hydra.py -v -t https://example.com/login -u admin -p pass.txt
```

## 📝 Logging

The tool creates detailed logs in `python_hydra.log`:

- Request/response details
- Success/failure detection
- Error messages
- Performance statistics

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚡ Performance Tips

- **Thread count**: Start with 5-10 threads, increase based on target response
- **Delay**: Use 0.5-2 second delays to avoid detection
- **Wordlists**: Use targeted wordlists for better success rates
- **Session cookies**: Maintain valid sessions when possible

## 🎓 Educational Use

This tool is excellent for:

- Learning about web application security
- Understanding authentication mechanisms
- Practicing penetration testing techniques
- Security research and testing

## 📞 Support

For issues, questions, or contributions:

1. Check the troubleshooting section
2. Review the logs for error details
3. Open an issue on the repository
4. Ensure you're using the latest version

---

**Remember: Always use this tool responsibly and legally!** 🛡️

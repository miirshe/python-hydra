# 🐍 Python Hydra v2.0

**HTTP Authentication Brute Force Tool**

A professional and powerful tool for penetration testing HTTP authentication systems. Built with threading support, strong browser headers, and simple, reliable detection logic.

## 👨‍💻 Author

**Abdikafi Isse Isak (miirshe)**  
Email: miirshe@gmail.com  
Software Engineer | AI, Web & Cybersecurity Enthusiast

## 🚀 Features

- **Strong Browser Headers** - Realistic browser fingerprinting
- **Multi-threading** - Fast brute force attacks
- **Session Management** - Proper cookie and header handling
- **Simple Logic** - Direct failure message detection
- **Progress Tracking** - Real-time attack progress
- **Results Export** - JSON output with statistics
- **Config Support** - JSON configuration files

## 📋 Requirements

- Python 3.7+
- `requests` library
- `concurrent.futures` (built-in)
- `argparse` (built-in)

## 🔧 Installation

### Option 1: Virtual Environment (Recommended)

**Step 1: Create Virtual Environment**
```bash
# Create a virtual environment
python3 -m venv python_hydra_env

# Activate the virtual environment
# On Linux/Mac:
source python_hydra_env/bin/activate

# On Windows:
python_hydra_env\Scripts\activate
```

**Step 2: Install Dependencies**
```bash
# Install requirements
pip install -r requirements.txt
```

**Step 3: Run the Tool**
```bash
# Your virtual environment is now active
python python_hydra.py -h
```

**Step 4: Deactivate When Done**
```bash
deactivate
```

### Option 2: Using pipx (Alternative)

```bash
# Install pipx if not available
sudo apt install pipx

# Install in isolated environment
pipx install -r requirements.txt
```

### Option 3: System-wide Installation (Not Recommended)

```bash
# Only if you know what you're doing
pip install -r requirements.txt --break-system-packages
```

## 🎯 Usage

### Basic Usage

```bash
# Test single username with password list
python python_hydra.py -t https://example.com/login -u admin -p pass.txt -f "Invalid credentials"

# Test multiple usernames
python python_hydra.py -t https://example.com/login -U users.txt -p pass.txt -f "Login failed"

# With custom delay and threads
python python_hydra.py -t https://example.com/login -u admin -p pass.txt -f "Invalid password" --delay 0.3 --threads 10
```

### Command Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-t, --target` | Target URL | ✅ Yes |
| `-u, --username` | Username or username file | No |
| `-U, --usernames` | Username file | No |
| `-p, --password` | Password file | No |
| `-P, --passwords` | Password file (alternative) | No |
| `-f, --failure` | Failure message to detect | ✅ Yes |
| `-c, --config` | Configuration file | No |
| `-o, --output` | Output file for results | No |
| `--delay` | Delay between requests (seconds) | No |
| `--threads` | Number of threads | No |
| `--stop-first` | Stop on first successful login | No |
| `--verbose, -v` | Verbose output | No |

### Configuration File

Create `config.json`:
```json
{
  "target": "https://example.com/login",
  "cookies": {
    "PHPSESSID": "your_session_id_here"
  },
  "delay": 0.5,
  "max_workers": 5,
  "stop_on_first": true
}
```

Then run:
```bash
python python_hydra.py -c config.json -u admin -p pass.txt -f "Invalid credentials"
```

## 📁 File Structure

```
python-hydra/
├── python_hydra.py      # Main tool
├── requirements.txt      # Python dependencies
├── README.md           # This file
├── pass.txt            # Password wordlist (create your own)
├── users.txt           # Username list (optional)
└── config.json         # Configuration file (optional)
```

## 🔍 How It Works

The tool uses the same logic as your working static code:

```python
# Your working approach:
if "Username or Password is invalid" not in response.text:
    print(f"[+] Possible success with password: {pwd}")

# Tool's approach:
if failure_message.lower() not in response.text.lower():
    return True, "Success! Failure message not found"
```

**Key Features:**
1. **Strong Headers** - Realistic browser fingerprinting
2. **Session Management** - Maintains cookies and headers
3. **Multi-threading** - Fast parallel requests
4. **Simple Detection** - Direct failure message checking
5. **Progress Tracking** - Real-time attack status

## 🛡️ Security Notes

- **Legal Use Only** - Only test systems you own or have permission to test
- **Rate Limiting** - Use `--delay` to avoid overwhelming targets
- **Session Management** - Proper cookies help avoid detection
- **Headers** - Realistic browser headers reduce blocking

## 🐛 Troubleshooting

### "externally-managed-environment" Error

This error occurs on modern Linux systems (Kali, Ubuntu 22.04+, etc.) that protect system Python packages.

**Solution: Use Virtual Environment**
```bash
# Create and activate virtual environment
python3 -m venv python_hydra_env
source python_hydra_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tool
python python_hydra.py -h
```

### Common Issues

1. **Permission Denied**: Use virtual environment or `sudo` (not recommended)
2. **Module Not Found**: Ensure virtual environment is activated
3. **Connection Errors**: Check target URL and network connectivity
4. **Rate Limiting**: Increase `--delay` value

## 📊 Example Output

```
🚀 Starting brute force attack on https://example.com/login
👥 Testing 1 usernames with 1000 passwords
🔢 Total combinations: 1000
❌ Failure message: 'Invalid credentials'

[+] 🎯 SUCCESS: admin:secret123 - Success! Failure message 'Invalid credentials' not found in response
📊 Progress: 500/1000 attempts

🏁 Brute force attack completed!
✅ Successful attempts: 1
❌ Failed attempts: 999
📈 Total attempts: 1000

🎯 SUCCESSFUL CREDENTIALS FOUND:
👤 Username: admin
🔑 Password: secret123
💬 Message: Success! Failure message 'Invalid credentials' not found in response
```

## 📝 License

MIT License - See LICENSE file for details.

## ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**. The author is not responsible for any misuse. Always ensure you have proper authorization before testing any system.

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve the tool.

---

**Happy Hacking! 🎯**

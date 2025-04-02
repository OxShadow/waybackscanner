import requests
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from urllib.parse import urlparse, urlencode, parse_qs
import re
from threading import Thread
from datetime import datetime


class DualOutputWaybackScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Wayback Scanner Pro - Author:ss GitHub:https://github.com/OxShadow")
        self.root.geometry("850x750")
        self.setup_ui()
        self.setup_crawler()

        # Configure text tags for colored logging
        self.log_area.tag_config("info", foreground="blue")
        self.log_area.tag_config("success", foreground="green")
        self.log_area.tag_config("warning", foreground="orange")
        self.log_area.tag_config("error", foreground="red")
        self.log_area.tag_config("match", foreground="#006400")  # Dark green
        self.log_area.tag_config("debug", foreground="gray")

    def setup_ui(self):
        """Configure the user interface with dual output options"""
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Configure colors
        self.style.configure('.', background='#f0f0f0', foreground='black')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', foreground='black')
        self.style.configure('TButton', background='#4CAF50', foreground='white')
        self.style.map('TButton', background=[('active', '#45a049')])
        self.style.configure('Red.TButton', background='#f44336')
        self.style.map('Red.TButton', background=[('active', '#d32f2f')])

        # Main controls frame
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)

        # Domain input
        ttk.Label(control_frame, text="Domain:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.domain_entry = ttk.Entry(control_frame, width=50)
        self.domain_entry.grid(row=0, column=1, sticky=tk.W, padx=5)

        # Output files
        ttk.Label(control_frame, text="All URLs File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.all_output_entry = ttk.Entry(control_frame, width=50)
        self.all_output_entry.grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Button(control_frame, text="Browse...", command=lambda: self.browse_file(self.all_output_entry)).grid(row=1,
                                                                                                                  column=2,
                                                                                                                  padx=5)

        ttk.Label(control_frame, text="Interesting URLs File:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.interesting_output_entry = ttk.Entry(control_frame, width=50)
        self.interesting_output_entry.grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Button(control_frame, text="Browse...",
                   command=lambda: self.browse_file(self.interesting_output_entry)).grid(row=2, column=2, padx=5)

        # Delay setting
        ttk.Label(control_frame, text="Delay (sec):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.delay_entry = ttk.Entry(control_frame, width=10)
        self.delay_entry.insert(0, "1.0")
        self.delay_entry.grid(row=3, column=1, sticky=tk.W, padx=5)

        # Action buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        self.start_button = ttk.Button(button_frame, text="Start Scanning", command=self.start_crawling)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_crawling, state=tk.DISABLED,
                                      style='Red.TButton')
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Progress area
        progress_frame = ttk.Frame(self.root, padding="10")
        progress_frame.pack(fill=tk.BOTH, expand=True)

        self.progress_label = ttk.Label(progress_frame,
                                        text="Ready - This may take time for large domains, please wait...")
        self.progress_label.pack(anchor=tk.W)

        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)

        # Log area
        self.log_area = scrolledtext.ScrolledText(
            progress_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#ffffff',
            fg='#333333',
            insertbackground='black',
            selectbackground='#4CAF50',
            selectforeground='white'
        )
        self.log_area.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, ipady=2)

    def setup_crawler(self):
        """Initialize crawler settings"""
        self.is_running = False
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WaybackScannerPro/1.0 (https://github.com/OxShadow)',
            'Accept': 'text/plain'
        })
        self.api_url = "https://web.archive.org/cdx/search/cdx"

        # File extensions to filter for
        self.file_extensions = [
            'zip', 'txt', 'config', 'db', 'log', 'tar',
            'gz', 'rar', '7z', 'xml', 'json', 'sql',
            'csv', 'bak', 'conf', 'ini', 'env', 'pem',
            'key', 'cer', 'pfx', 'p12', 'jks', 'keystore'
        ]

        # URL parameters that might indicate files
        self.file_params = [
            'url', 'file', 'filepath', 'userid', 'token',
            'ak', 'sk', 'secret', 'password', 'key',
            'accesskey', 'privatekey', 'credential', 'auth'
        ]

        # Compile regex patterns for better performance
        self.ext_pattern = re.compile(
            r'\.(' + '|'.join(self.file_extensions) + r')(\?|$|/)',
            re.IGNORECASE
        )
        self.param_pattern = re.compile(
            r'[?&](' + '|'.join(self.file_params) + r')=([^&]+)',
            re.IGNORECASE
        )

    def browse_file(self, entry_widget):
        """Open file dialog to select output file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Select output file"
        )
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

    def log(self, message, tag=None):
        """Add message to log with optional formatting"""
        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.see(tk.END)
        self.root.update()

    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(message)
        self.root.update()

    def start_crawling(self):
        """Start the scanning process"""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Domain is required")
            return

        all_output_file = self.all_output_entry.get().strip()
        interesting_output_file = self.interesting_output_entry.get().strip()

        if not all_output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            all_output_file = f"wayback_all_{domain}_{timestamp}.txt"
            self.all_output_entry.delete(0, tk.END)
            self.all_output_entry.insert(0, all_output_file)

        if not interesting_output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            interesting_output_file = f"wayback_interesting_{domain}_{timestamp}.txt"
            self.interesting_output_entry.delete(0, tk.END)
            self.interesting_output_entry.insert(0, interesting_output_file)

        try:
            delay = max(0.5, float(self.delay_entry.get()))
        except ValueError:
            messagebox.showerror("Error", "Delay must be a number")
            return

        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.progress['value'] = 0

        # Start scanning in a new thread
        Thread(
            target=self.scan_domain,
            args=(domain, all_output_file, interesting_output_file, delay),
            daemon=True
        ).start()

    def stop_crawling(self):
        """Stop the scanning process"""
        self.is_running = False
        self.log("[!] Scan stopping after current request completes...", "warning")
        self.update_status("Stopping...")

    def is_interesting_url(self, url):
        """Check if URL matches our interesting patterns"""
        # Check for file extensions
        if self.ext_pattern.search(url):
            return True

        # Check for interesting query parameters
        if self.param_pattern.search(url):
            return True

        return False

    def scan_domain(self, domain, all_output_file, interesting_output_file, delay):
        """Main scanning function with dual output"""
        params = {
            'url': f'*.{domain}/*',
            'collapse': 'urlkey',
            'output': 'text',
            'fl': 'original',
            'showResumeKey': 'true'
        }

        self.log(f"[*] Starting scan for: {domain}", "info")
        self.log(f"[*] All URLs file: {all_output_file}", "info")
        self.log(f"[*] Interesting URLs file: {interesting_output_file}", "info")
        self.log(f"[*] Request delay: {delay} seconds", "info")
        self.update_status(f"Scanning {domain}...")

        total_urls = 0
        interesting_urls = 0
        resume_key = None
        start_time = time.time()

        try:
            with open(all_output_file, 'w', encoding='utf-8') as all_f, \
                    open(interesting_output_file, 'w', encoding='utf-8') as interesting_f:

                # Write headers to interesting file
                interesting_f.write(f"# Wayback Scanner Results - {domain}\n")
                interesting_f.write(f"# Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                interesting_f.write(f"# Filter criteria:\n")
                interesting_f.write(f"# - File extensions: {', '.join(self.file_extensions)}\n")
                interesting_f.write(f"# - Sensitive parameters: {', '.join(self.file_params)}\n")
                interesting_f.write("#" * 80 + "\n\n")

                while self.is_running:
                    if resume_key:
                        params['resumeKey'] = resume_key
                        self.log(f"[>] Continuing with resumeKey: {resume_key[:10]}...", "debug")

                    time.sleep(delay)
                    try:
                        response = self.session.get(
                            self.api_url,
                            params=params,
                            timeout=60
                        )
                        response.raise_for_status()
                    except Exception as e:
                        self.log(f"[!] Request failed: {str(e)}", "error")
                        break

                    urls = response.text.strip().split('\n')
                    if not urls:
                        self.log("[*] No more data available", "info")
                        break

                    batch_count = 0
                    batch_interesting = 0

                    for url in urls:
                        if not url:
                            continue

                        total_urls += 1
                        batch_count += 1

                        # Write to all URLs file
                        all_f.write(url + "\n")

                        if self.is_interesting_url(url):
                            interesting_urls += 1
                            batch_interesting += 1
                            interesting_f.write(url + "\n")
                            self.log(f"[+] Interesting URL found: {url}", "match")

                    all_f.flush()
                    interesting_f.flush()

                    # Update UI
                    self.log(
                        f"[*] Processed {batch_count} URLs (Batch interesting: {batch_interesting}, "
                        f"Total: {total_urls}, Interesting: {interesting_urls})",
                        "info"
                    )

                    self.progress_label.config(
                        text=f"Processed: {total_urls} | Interesting: {interesting_urls} | Last batch: {batch_interesting}"
                    )
                    self.progress['value'] = total_urls % 100
                    self.update_status(f"Scanning... Found {interesting_urls} interesting URLs")
                    self.root.update()

                    # Get next resumeKey
                    resume_key = response.headers.get('Resume-Key')
                    if not resume_key:
                        break

        except Exception as e:
            self.log(f"[!] Error occurred: {str(e)}", "error")
        finally:
            elapsed = (time.time() - start_time) / 60
            self.log("\n[*] Scan completed!", "info")
            self.log(f"[*] Total URLs processed: {total_urls}", "info")
            self.log(f"[*] Interesting URLs found: {interesting_urls}", "success")
            self.log(f"[*] Time elapsed: {elapsed:.2f} minutes", "info")
            self.log(f"[*] All URLs saved to: {all_output_file}", "info")
            self.log(f"[*] Interesting URLs saved to: {interesting_output_file}", "info")

            self.is_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress['value'] = 100
            self.update_status(f"Done. Found {interesting_urls} interesting URLs in {elapsed:.1f} minutes")


if __name__ == "__main__":
    root = tk.Tk()
    app = DualOutputWaybackScanner(root)
    root.mainloop()

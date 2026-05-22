#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
    DECODELABS CYBERSECURITY TRAINING - PROJECT 1
    PASSWORD STRENGTH CHECKER - MASTER EDITION
    Batch: 2026 | Powered by DecodeLabs
═══════════════════════════════════════════════════════════════════════════════

A comprehensive password validation tool featuring:
- Command-Line Interface (CLI)
- Graphical User Interface (GUI)
- Interactive Demo Mode
- Real-time Security Analysis
- Industry-Standard Validation

Author: DecodeLabs Training Participant
Project: Password Strength Checker
Status: Production Ready
"""

import re
import string
import sys
from typing import Dict, List, Tuple

# Check for GUI availability
GUI_AVAILABLE = True
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
except ImportError:
    GUI_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# CORE PASSWORD ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class PasswordStrengthChecker:
    """
    Professional password strength analyzer implementing industry-standard
    security validation rules and entropy analysis.
    """
    
    # Database of commonly leaked passwords (Top 20)
    COMMON_PASSWORDS = {
        'password', '12345678', 'qwerty', 'abc123', 'monkey', 
        'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
        'master', 'sunshine', 'ashley', 'bailey', 'shadow',
        'password123', 'admin', 'welcome', '123456789', 'password1'
    }
    
    def __init__(self):
        """Initialize password checker with security thresholds"""
        self.min_length = 8
        self.recommended_length = 12
        self.strong_length = 16
        
    def analyze_password(self, password: str) -> Dict:
        """
        Comprehensive password analysis with detailed security metrics.
        
        Args:
            password: The password string to analyze
            
        Returns:
            Dictionary containing:
            - strength: WEAK/MEDIUM/STRONG
            - score: 0-100 security score
            - feedback: List of detailed checks
            - color: Color code for UI display
            - passed: Boolean if meets minimum standards
        """
        if not password:
            return {
                'strength': 'Invalid',
                'score': 0,
                'feedback': ['❌ Password cannot be empty'],
                'color': 'red',
                'passed': False,
                'length': 0,
                'variety_ratio': 0
            }
        
        score = 0
        feedback = []
        length = len(password)
        
        # ═══════════════════════════════════════════════════════════════
        # CHECK 1: LENGTH VERIFICATION
        # ═══════════════════════════════════════════════════════════════
        if length < self.min_length:
            feedback.append(f'❌ Too short: Use at least {self.min_length} characters')
        elif length >= self.strong_length:
            score += 30
            feedback.append(f'✓ Excellent length: {length} characters')
        elif length >= self.recommended_length:
            score += 20
            feedback.append(f'✓ Good length: {length} characters')
        else:
            score += 10
            feedback.append(f'⚠ Acceptable length: {length} characters (recommend {self.recommended_length}+)')
        
        # ═══════════════════════════════════════════════════════════════
        # CHECK 2: CHARACTER TYPE ANALYSIS
        # ═══════════════════════════════════════════════════════════════
        
        # Uppercase letters (A-Z)
        if any(c.isupper() for c in password):
            score += 10
            feedback.append('✓ Contains uppercase letters')
        else:
            feedback.append('❌ Missing uppercase letters (A-Z)')
        
        # Lowercase letters (a-z)
        if any(c.islower() for c in password):
            score += 10
            feedback.append('✓ Contains lowercase letters')
        else:
            feedback.append('❌ Missing lowercase letters (a-z)')
        
        # Numbers (0-9)
        if any(c.isdigit() for c in password):
            score += 10
            feedback.append('✓ Contains numbers')
        else:
            feedback.append('❌ Missing numbers (0-9)')
        
        # Special symbols
        if any(c in string.punctuation for c in password):
            score += 15
            feedback.append('✓ Contains special symbols')
        else:
            feedback.append('❌ Missing special symbols (!@#$%^&*)')
        
        # ═══════════════════════════════════════════════════════════════
        # CHECK 3: SECURITY PATTERN DETECTION
        # ═══════════════════════════════════════════════════════════════
        
        # Common password check
        if password.lower() not in self.COMMON_PASSWORDS:
            score += 10
            feedback.append('✓ Not a commonly used password')
        else:
            score -= 10
            feedback.append('❌ CRITICAL: This is a commonly leaked password!')
        
        # Sequential character detection
        if not self._has_sequential_chars(password):
            score += 5
            feedback.append('✓ No sequential patterns detected')
        else:
            feedback.append('⚠ Contains sequential characters (e.g., abc, 123)')
        
        # Character repetition check
        if not self._has_repeated_chars(password):
            score += 5
            feedback.append('✓ No excessive character repetition')
        else:
            feedback.append('⚠ Contains repeated characters (e.g., aaa, 111)')
        
        # ═══════════════════════════════════════════════════════════════
        # CHECK 4: ENTROPY ANALYSIS
        # ═══════════════════════════════════════════════════════════════
        unique_chars = len(set(password))
        variety_ratio = unique_chars / length if length > 0 else 0
        
        if variety_ratio > 0.8:
            score += 5
            feedback.append('✓ Excellent character variety')
        elif variety_ratio < 0.5:
            feedback.append('⚠ Low character variety - consider more unique characters')
        
        # ═══════════════════════════════════════════════════════════════
        # CALCULATE FINAL STRENGTH RATING
        # ═══════════════════════════════════════════════════════════════
        final_score = max(0, min(score, 100))  # Clamp between 0-100
        strength, color = self._calculate_strength_level(final_score)
        
        return {
            'strength': strength,
            'score': final_score,
            'color': color,
            'feedback': feedback,
            'passed': final_score >= 60,
            'length': length,
            'variety_ratio': variety_ratio
        }
    
    def _has_sequential_chars(self, password: str) -> bool:
        """Detect sequential character patterns (abc, 123, xyz, etc.)"""
        sequences = [
            'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij',
            'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr',
            'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
            '012', '123', '234', '345', '456', '567', '678', '789'
        ]
        password_lower = password.lower()
        return any(seq in password_lower or seq[::-1] in password_lower 
                  for seq in sequences)
    
    def _has_repeated_chars(self, password: str) -> bool:
        """Check for excessive character repetition (3+ same chars in a row)"""
        return bool(re.search(r'(.)\1{2,}', password))
    
    def _calculate_strength_level(self, score: int) -> Tuple[str, str]:
        """Determine password strength level and color based on score"""
        if score >= 85:
            return 'STRONG', 'green'
        elif score >= 60:
            return 'MEDIUM', 'orange'
        else:
            return 'WEAK', 'red'


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND-LINE INTERFACE (CLI)
# ═══════════════════════════════════════════════════════════════════════════

class CLI_Interface:
    """Professional command-line interface for password checking"""
    
    def __init__(self):
        self.checker = PasswordStrengthChecker()
        
    def print_header(self):
        """Display professional header"""
        print("\n" + "═"*76)
        print("  🔐 DECODELABS PASSWORD STRENGTH CHECKER")
        print("  Project 1: Defensive Logic | Batch 2026")
        print("═"*76 + "\n")
    
    def print_analysis_results(self, analysis: Dict):
        """Display comprehensive password analysis results"""
        # Strength indicators
        strength_symbols = {
            'WEAK': '🔴',
            'MEDIUM': '🟠',
            'STRONG': '🟢',
            'Invalid': '⚪'
        }
        
        symbol = strength_symbols.get(analysis['strength'], '⚪')
        
        print("\n" + "─"*76)
        print("  PASSWORD ANALYSIS COMPLETE")
        print("─"*76)
        
        # Main metrics
        print(f"\n  {symbol} Strength Level: {analysis['strength']}")
        print(f"  📊 Security Score: {analysis['score']}/100")
        print(f"  📏 Length: {analysis['length']} characters")
        if analysis['length'] > 0:
            print(f"  🎨 Character Variety: {analysis['variety_ratio']:.0%}")
        
        # Detailed feedback
        print(f"\n  DETAILED SECURITY ANALYSIS:")
        print("  " + "─"*72)
        for item in analysis['feedback']:
            print(f"  {item}")
        
        # Recommendations
        print(f"\n  RECOMMENDATIONS:")
        print("  " + "─"*72)
        
        if analysis['strength'] == 'WEAK':
            print("  ⚠️  CRITICAL: This password does not meet security standards!")
            print("  → Use at least 12 characters (16+ recommended)")
            print("  → Include uppercase, lowercase, numbers, AND symbols")
            print("  → Avoid common words and patterns")
        elif analysis['strength'] == 'MEDIUM':
            print("  ⚡ This password is acceptable but can be improved:")
            print("  → Consider increasing length to 16+ characters")
            print("  → Add more special symbols for enhanced security")
            print("  → Maximize character variety")
        else:
            print("  ✅ Excellent! This password meets strong security standards.")
            print("  → Never reuse this password across accounts")
            print("  → Store it securely (use a password manager)")
            print("  → Change it regularly every 90 days")
        
        print("\n" + "═"*76 + "\n")
    
    def get_password_input(self) -> str:
        """Get password input (with hidden typing if available)"""
        print("Enter a password to check its strength:")
        print("(Your input will be hidden for security)\n")
        
        try:
            import getpass
            return getpass.getpass("Password: ")
        except (KeyboardInterrupt, EOFError):
            print("\n\nOperation cancelled.")
            return None
        except:
            # Fallback to regular input
            return input("Password: ")
    
    def run(self):
        """Main CLI loop"""
        self.print_header()
        print("Welcome to the Password Strength Checker!")
        print("This tool evaluates passwords against industry security standards.\n")
        
        while True:
            password = self.get_password_input()
            
            if password is None:
                break
            
            analysis = self.checker.analyze_password(password)
            self.print_analysis_results(analysis)
            
            print("Check another password? (y/n): ", end="")
            try:
                choice = input().strip().lower()
                if choice not in ['y', 'yes']:
                    break
                print("\n" + "─"*76 + "\n")
            except (KeyboardInterrupt, EOFError):
                break
        
        print("\n" + "═"*76)
        print("  Thank you for using DecodeLabs Password Strength Checker!")
        print("  Stay secure! 🛡️")
        print("═"*76 + "\n")


# ═══════════════════════════════════════════════════════════════════════════
# GRAPHICAL USER INTERFACE (GUI)
# ═══════════════════════════════════════════════════════════════════════════

if GUI_AVAILABLE:
    class GUI_Interface:
        """Premium graphical interface with real-time analysis"""
        
        def __init__(self, root):
            self.root = root
            self.checker = PasswordStrengthChecker()
            self.root.title("DecodeLabs Password Strength Checker")
            self.root.geometry("750x700")
            self.root.resizable(False, False)
            
            # Color scheme
            self.colors = {
                'primary': '#2c3e50',
                'secondary': '#34495e',
                'success': '#27ae60',
                'warning': '#f39c12',
                'danger': '#e74c3c',
                'bg': '#ecf0f1',
                'text': '#2c3e50'
            }
            
            self.root.configure(bg=self.colors['bg'])
            self.setup_styles()
            self.create_widgets()
            
        def setup_styles(self):
            """Configure modern UI styles"""
            style = ttk.Style()
            style.theme_use('clam')
            
        def create_widgets(self):
            """Build all GUI components"""
            # ═══════════════════════════════════════════════════════════
            # HEADER SECTION
            # ═══════════════════════════════════════════════════════════
            header_frame = tk.Frame(self.root, bg=self.colors['primary'], height=100)
            header_frame.pack(fill=tk.X)
            header_frame.pack_propagate(False)
            
            title_label = tk.Label(
                header_frame,
                text="🔐 PASSWORD STRENGTH CHECKER",
                font=('Arial', 20, 'bold'),
                bg=self.colors['primary'],
                fg='white'
            )
            title_label.pack(pady=20)
            
            subtitle = tk.Label(
                header_frame,
                text="DecodeLabs Cybersecurity Training | Project 1 | Batch 2026",
                font=('Arial', 10),
                bg=self.colors['primary'],
                fg='#95a5a6'
            )
            subtitle.pack()
            
            # ═══════════════════════════════════════════════════════════
            # MAIN CONTENT AREA
            # ═══════════════════════════════════════════════════════════
            content_frame = tk.Frame(self.root, bg=self.colors['bg'])
            content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=20)
            
            # Password input
            input_label = tk.Label(
                content_frame,
                text="Enter Password to Analyze:",
                font=('Arial', 12, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['text']
            )
            input_label.pack(anchor=tk.W, pady=(0, 8))
            
            input_frame = tk.Frame(content_frame, bg=self.colors['bg'])
            input_frame.pack(fill=tk.X, pady=(0, 15))
            
            self.password_var = tk.StringVar()
            self.password_var.trace('w', self.on_password_change)
            
            self.password_entry = tk.Entry(
                input_frame,
                textvariable=self.password_var,
                font=('Arial', 13),
                show='●',
                relief=tk.SOLID,
                borderwidth=2
            )
            self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=10)
            
            self.show_password_var = tk.BooleanVar()
            show_btn = tk.Checkbutton(
                input_frame,
                text="Show",
                variable=self.show_password_var,
                command=self.toggle_password_visibility,
                bg=self.colors['bg'],
                font=('Arial', 10),
                cursor='hand2'
            )
            show_btn.pack(side=tk.LEFT, padx=(12, 0))
            
            # ═══════════════════════════════════════════════════════════
            # STRENGTH INDICATOR
            # ═══════════════════════════════════════════════════════════
            strength_frame = tk.Frame(content_frame, bg=self.colors['bg'])
            strength_frame.pack(fill=tk.X, pady=(0, 15))
            
            tk.Label(
                strength_frame,
                text="Strength:",
                font=('Arial', 11, 'bold'),
                bg=self.colors['bg']
            ).pack(side=tk.LEFT)
            
            self.strength_label = tk.Label(
                strength_frame,
                text="NOT ANALYZED",
                font=('Arial', 11, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['text']
            )
            self.strength_label.pack(side=tk.LEFT, padx=12)
            
            self.score_label = tk.Label(
                strength_frame,
                text="Score: 0/100",
                font=('Arial', 11),
                bg=self.colors['bg']
            )
            self.score_label.pack(side=tk.LEFT)
            
            # Progress bar
            self.progress = ttk.Progressbar(
                content_frame,
                length=700,
                mode='determinate',
                maximum=100
            )
            self.progress.pack(fill=tk.X, pady=(0, 20))
            
            # ═══════════════════════════════════════════════════════════
            # FEEDBACK AREA
            # ═══════════════════════════════════════════════════════════
            feedback_label = tk.Label(
                content_frame,
                text="Security Analysis:",
                font=('Arial', 12, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['text']
            )
            feedback_label.pack(anchor=tk.W, pady=(0, 8))
            
            self.feedback_text = scrolledtext.ScrolledText(
                content_frame,
                height=16,
                font=('Consolas', 10),
                relief=tk.SOLID,
                borderwidth=2,
                wrap=tk.WORD
            )
            self.feedback_text.pack(fill=tk.BOTH, expand=True)
            self.feedback_text.config(state=tk.DISABLED)
            self.show_initial_message()
            
            # ═══════════════════════════════════════════════════════════
            # ACTION BUTTONS
            # ═══════════════════════════════════════════════════════════
            button_frame = tk.Frame(content_frame, bg=self.colors['bg'])
            button_frame.pack(fill=tk.X, pady=(18, 0))
            
            analyze_btn = tk.Button(
                button_frame,
                text="🔍 Analyze Password",
                command=self.analyze_password,
                bg=self.colors['primary'],
                fg='white',
                font=('Arial', 11, 'bold'),
                relief=tk.FLAT,
                cursor='hand2',
                padx=25,
                pady=12
            )
            analyze_btn.pack(side=tk.LEFT, padx=(0, 12))
            
            clear_btn = tk.Button(
                button_frame,
                text="🗑 Clear",
                command=self.clear_all,
                bg=self.colors['secondary'],
                fg='white',
                font=('Arial', 11),
                relief=tk.FLAT,
                cursor='hand2',
                padx=25,
                pady=12
            )
            clear_btn.pack(side=tk.LEFT)
            
            # Info button
            info_btn = tk.Button(
                button_frame,
                text="ℹ️ Help",
                command=self.show_help,
                bg='#3498db',
                fg='white',
                font=('Arial', 11),
                relief=tk.FLAT,
                cursor='hand2',
                padx=25,
                pady=12
            )
            info_btn.pack(side=tk.RIGHT)
            
        def show_initial_message(self):
            """Show welcome message in feedback area"""
            self.feedback_text.config(state=tk.NORMAL)
            self.feedback_text.delete(1.0, tk.END)
            welcome = """
═══════════════════════════════════════════════════════════════════
   WELCOME TO PASSWORD STRENGTH CHECKER
═══════════════════════════════════════════════════════════════════

Enter a password above to see real-time security analysis.

This tool checks:
  ✓ Password length (minimum 8, recommended 12+)
  ✓ Character types (uppercase, lowercase, numbers, symbols)
  ✓ Common password detection
  ✓ Sequential pattern recognition
  ✓ Character variety and entropy

Security Standards:
  🔴 WEAK (0-59):    Does not meet security standards
  🟠 MEDIUM (60-84): Acceptable but improvable
  🟢 STRONG (85-100): Meets industry standards

Start typing to begin analysis!
            """
            self.feedback_text.insert(tk.END, welcome)
            self.feedback_text.config(state=tk.DISABLED)
            
        def toggle_password_visibility(self):
            """Toggle password visibility"""
            if self.show_password_var.get():
                self.password_entry.config(show='')
            else:
                self.password_entry.config(show='●')
        
        def on_password_change(self, *args):
            """Real-time password analysis as user types"""
            password = self.password_var.get()
            if password:
                self.analyze_password()
            else:
                self.clear_results()
        
        def analyze_password(self):
            """Perform and display password analysis"""
            password = self.password_var.get()
            
            if not password:
                messagebox.showwarning(
                    "No Password",
                    "Please enter a password to analyze."
                )
                return
            
            analysis = self.checker.analyze_password(password)
            self.update_strength_display(analysis)
            self.update_feedback_display(analysis)
            self.update_progress_bar(analysis['score'])
        
        def update_strength_display(self, analysis: Dict):
            """Update strength indicator"""
            strength_symbols = {
                'WEAK': '🔴',
                'MEDIUM': '🟠',
                'STRONG': '🟢',
                'Invalid': '⚪'
            }
            
            symbol = strength_symbols.get(analysis['strength'], '⚪')
            self.strength_label.config(
                text=f"{symbol} {analysis['strength']}",
                fg=analysis['color']
            )
            self.score_label.config(text=f"Score: {analysis['score']}/100")
        
        def update_feedback_display(self, analysis: Dict):
            """Update feedback text area with detailed analysis"""
            self.feedback_text.config(state=tk.NORMAL)
            self.feedback_text.delete(1.0, tk.END)
            
            # Header
            header = "═"*67 + "\n"
            header += "  PASSWORD SECURITY ANALYSIS\n"
            header += "═"*67 + "\n\n"
            self.feedback_text.insert(tk.END, header)
            
            # Metrics
            metrics = f"📏 Length: {analysis['length']} characters\n"
            metrics += f"📊 Security Score: {analysis['score']}/100\n"
            metrics += f"🎨 Character Variety: {analysis['variety_ratio']:.0%}\n\n"
            self.feedback_text.insert(tk.END, metrics)
            
            # Detailed feedback
            self.feedback_text.insert(tk.END, "DETAILED SECURITY CHECKS:\n")
            self.feedback_text.insert(tk.END, "─" * 67 + "\n")
            for item in analysis['feedback']:
                self.feedback_text.insert(tk.END, f"{item}\n")
            
            # Recommendations
            self.feedback_text.insert(tk.END, f"\n{'═'*67}\n")
            self.feedback_text.insert(tk.END, "RECOMMENDATIONS:\n")
            self.feedback_text.insert(tk.END, "─" * 67 + "\n")
            
            if analysis['strength'] == 'WEAK':
                recs = [
                    "⚠️  CRITICAL: This password does not meet security standards!",
                    "→ Use at least 12 characters (16+ recommended)",
                    "→ Include uppercase, lowercase, numbers, AND symbols",
                    "→ Avoid common words and sequential patterns",
                    "→ Never use personal information or dictionary words"
                ]
            elif analysis['strength'] == 'MEDIUM':
                recs = [
                    "⚡ This password is acceptable but can be improved:",
                    "→ Consider increasing length to 16+ characters",
                    "→ Add more special symbols for enhanced security",
                    "→ Maximize character variety and uniqueness",
                    "→ Avoid predictable patterns"
                ]
            else:
                recs = [
                    "✅ Excellent! This password meets strong security standards.",
                    "→ Never reuse this password across different accounts",
                    "→ Store it securely using a password manager",
                    "→ Change it regularly every 90 days",
                    "→ Enable two-factor authentication when available"
                ]
            
            for rec in recs:
                self.feedback_text.insert(tk.END, f"{rec}\n")
            
            # Security facts
            self.feedback_text.insert(tk.END, f"\n{'═'*67}\n")
            self.feedback_text.insert(tk.END, "SECURITY FACTS:\n")
            self.feedback_text.insert(tk.END, "─" * 67 + "\n")
            self.feedback_text.insert(tk.END, "• 81% of breaches involve weak or stolen passwords\n")
            self.feedback_text.insert(tk.END, "• Average breach cost: $4.24 million\n")
            self.feedback_text.insert(tk.END, "• Strong passwords are your first line of defense\n")
            
            self.feedback_text.config(state=tk.DISABLED)
        
        def update_progress_bar(self, score: int):
            """Update progress bar with color coding"""
            self.progress['value'] = score
            
            style = ttk.Style()
            if score >= 85:
                style.configure("TProgressbar", background=self.colors['success'])
            elif score >= 60:
                style.configure("TProgressbar", background=self.colors['warning'])
            else:
                style.configure("TProgressbar", background=self.colors['danger'])
        
        def clear_results(self):
            """Clear analysis results"""
            self.strength_label.config(text="NOT ANALYZED", fg=self.colors['text'])
            self.score_label.config(text="Score: 0/100")
            self.progress['value'] = 0
            self.show_initial_message()
        
        def clear_all(self):
            """Clear everything"""
            self.password_var.set("")
            self.clear_results()
        
        def show_help(self):
            """Show help dialog"""
            help_text = """
PASSWORD STRENGTH CHECKER - HELP

HOW TO USE:
1. Type your password in the input field
2. Analysis updates automatically in real-time
3. Review the security score and recommendations
4. Use "Show" checkbox to reveal password
5. Click "Clear" to start over

SCORING SYSTEM:
• Length: 10-30 points (8+ chars required, 16+ ideal)
• Uppercase: 10 points
• Lowercase: 10 points
• Numbers: 10 points
• Symbols: 15 points
• Not common: 10 points
• No patterns: 5 points
• No repetition: 5 points
• Character variety: 5 points

STRENGTH LEVELS:
🔴 WEAK (0-59): Does not meet standards
🟠 MEDIUM (60-84): Acceptable but improvable
🟢 STRONG (85-100): Meets industry standards

BEST PRACTICES:
✓ Use 12+ characters (16+ recommended)
✓ Mix all character types
✓ Avoid personal information
✓ Don't reuse passwords
✓ Use a password manager
✓ Enable two-factor authentication

DecodeLabs Cybersecurity Training
Project 1 - Batch 2026
            """
            messagebox.showinfo("Help - Password Strength Checker", help_text)
        
        def run(self):
            """Start the GUI application"""
            self.root.mainloop()


# ═══════════════════════════════════════════════════════════════════════════
# DEMO MODE
# ═══════════════════════════════════════════════════════════════════════════

class DemoMode:
    """Interactive demonstration of the password checker"""
    
    def __init__(self):
        self.checker = PasswordStrengthChecker()
        
    def print_demo_header(self):
        """Print demo header"""
        print("\n" + "═"*76)
        print("  🎬 PASSWORD STRENGTH CHECKER - INTERACTIVE DEMO")
        print("  DecodeLabs Cybersecurity Training | Project 1 | Batch 2026")
        print("═"*76 + "\n")
    
    def demo_password(self, password: str, description: str):
        """Demonstrate password analysis"""
        print(f"📝 Example: {description}")
        print(f"🔑 Password: {'●' * len(password)} ({len(password)} characters)")
        
        analysis = self.checker.analyze_password(password)
        
        strength_emoji = {
            'WEAK': '🔴',
            'MEDIUM': '🟠',
            'STRONG': '🟢'
        }
        
        emoji = strength_emoji.get(analysis['strength'], '⚪')
        print(f"\n{emoji} RESULT: {analysis['strength']} | Score: {analysis['score']}/100")
        
        print("\nKey Findings:")
        for item in analysis['feedback'][:6]:
            print(f"  {item}")
        
        print("\n" + "─"*76 + "\n")
    
    def run(self):
        """Run interactive demonstration"""
        self.print_demo_header()
        
        print("This demo shows how different passwords are evaluated.")
        print("You'll see examples of WEAK, MEDIUM, and STRONG passwords.\n")
        
        input("Press ENTER to start the demonstration...")
        
        demos = [
            # Weak passwords
            ("hello", "Very weak - too short, no complexity"),
            ("password", "Common password - in breach databases"),
            ("12345678", "Only numbers - no diversity"),
            
            # Medium passwords
            ("Password123", "Has basics but missing symbols"),
            ("Welcome2024", "Better but has sequential pattern"),
            
            # Strong passwords
            ("MyP@ssw0rd2024!Secure", "Excellent - all requirements met"),
            ("Tr0ub@dor&3$Complex", "Strong - random and varied"),
        ]
        
        print("\n" + "═"*76)
        print("  SECTION 1: WEAK PASSWORDS (AVOID THESE!)")
        print("═"*76 + "\n")
        
        for password, desc in demos[:3]:
            self.demo_password(password, desc)
            input("Press ENTER for next example...")
        
        print("\n" + "═"*76)
        print("  SECTION 2: MEDIUM PASSWORDS (ACCEPTABLE)")
        print("═"*76 + "\n")
        
        for password, desc in demos[3:5]:
            self.demo_password(password, desc)
            input("Press ENTER for next example...")
        
        print("\n" + "═"*76)
        print("  SECTION 3: STRONG PASSWORDS (RECOMMENDED)")
        print("═"*76 + "\n")
        
        for password, desc in demos[5:]:
            self.demo_password(password, desc)
            if password != demos[-1][0]:
                input("Press ENTER for next example...")
        
        print("\n" + "═"*76)
        print("  📊 DEMO COMPLETE")
        print("═"*76 + "\n")
        
        print("Key Takeaways:")
        print("  ✅ Use 12+ characters (16+ recommended)")
        print("  ✅ Mix uppercase, lowercase, numbers, and symbols")
        print("  ✅ Avoid common words and patterns")
        print("  ✅ Never reuse passwords across accounts")
        print("  ✅ Use a password manager\n")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN MENU & APPLICATION LAUNCHER
# ═══════════════════════════════════════════════════════════════════════════

def show_main_menu():
    """Display main menu and handle mode selection"""
    print("\n" + "═"*76)
    print("  🔐 DECODELABS PASSWORD STRENGTH CHECKER - MASTER EDITION")
    print("  Project 1: Defensive Logic | Batch 2026")
    print("═"*76 + "\n")
    
    print("Choose your mode:\n")
    print("  1. 💻 Command-Line Interface (CLI)")
    print("     → Interactive terminal-based password checking")
    print("     → Hidden password input for security")
    print("     → Best for learning and quick checks\n")
    
    if GUI_AVAILABLE:
        print("  2. 🖥️  Graphical User Interface (GUI)")
        print("     → Modern window-based application")
        print("     → Real-time analysis as you type")
        print("     → Best for presentations and demonstrations\n")
    else:
        print("  2. 🖥️  Graphical User Interface (GUI) - NOT AVAILABLE")
        print("     → tkinter not installed on this system\n")
    
    print("  3. 🎬 Demo Mode")
    print("     → Guided demonstration with examples")
    print("     → See WEAK, MEDIUM, and STRONG passwords")
    print("     → Best for understanding the tool\n")
    
    print("  4. ℹ️  Information & Help")
    print("     → Learn about the project")
    print("     → Security best practices")
    print("     → Technical documentation\n")
    
    print("  5. ❌ Exit\n")
    
    print("─"*76)


def show_information():
    """Display project information and help"""
    print("\n" + "═"*76)
    print("  ℹ️  PROJECT INFORMATION")
    print("═"*76 + "\n")
    
    info = """
ABOUT THIS PROJECT:
This is Project 1 from the DecodeLabs Cybersecurity Industrial Training Kit.
It focuses on building defensive security logic through password validation.

PROJECT GOALS:
✓ Master string handling and conditional logic
✓ Understand password security principles
✓ Implement data validation techniques
✓ Learn entropy concepts in cybersecurity
✓ Build production-ready security tools

FEATURES:
• Real-time password strength analysis
• Industry-standard security checks
• Common password detection (20+ leaked passwords)
• Sequential pattern recognition
• Character repetition analysis
• Entropy and variety scoring
• Multiple interfaces (CLI, GUI, Demo)

SECURITY CHECKS PERFORMED:
1. Length Verification (8 min, 12 recommended, 16+ strong)
2. Character Types (uppercase, lowercase, numbers, symbols)
3. Common Password Detection (checks against breach database)
4. Sequential Pattern Detection (abc, 123, xyz)
5. Character Repetition Check (aaa, 111)
6. Entropy Analysis (character variety and uniqueness)

SCORING SYSTEM:
• Total possible: 100 points
• WEAK: 0-59 (does not meet standards)
• MEDIUM: 60-84 (acceptable but improvable)
• STRONG: 85-100 (meets industry standards)

SECURITY STATISTICS:
• 81% of hacking breaches involve weak or stolen passwords
• Average breach cost: $4.24 million
• Password validation is the first line of defense

BEST PRACTICES:
✓ Use at least 12 characters (16+ recommended)
✓ Include uppercase, lowercase, numbers, AND symbols
✓ Avoid dictionary words and personal information
✓ Don't use sequential patterns (abc, 123)
✓ Never reuse passwords across accounts
✓ Store passwords in a password manager
✓ Enable two-factor authentication
✓ Change passwords every 90 days

TECHNICAL DETAILS:
• Language: Python 3.7+
• Dependencies: Standard library only (no external packages)
• Complexity: O(n) linear time
• Design Pattern: Pythonic elegance with built-in functions
• Security: Implements "Gatekeeper Rule" validation

DECODELABS CONTACT:
📧 decodelabs.tech@gmail.com
🌐 www.decodelabs.tech
📱 +91 89330 06408
📍 Greater Lucknow, India

This tool is part of your journey to becoming a cybersecurity professional.
Master the fundamentals, then advance to Project 2: Hashing & Encryption!
    """
    
    print(info)
    print("═"*76 + "\n")
    input("Press ENTER to return to main menu...")


def main():
    """Main application entry point"""
    while True:
        try:
            show_main_menu()
            choice = input("Enter your choice (1-5): ").strip()
            
            if choice == '1':
                # CLI Mode
                cli = CLI_Interface()
                cli.run()
            
            elif choice == '2':
                # GUI Mode
                if GUI_AVAILABLE:
                    root = tk.Tk()
                    gui = GUI_Interface(root)
                    gui.run()
                else:
                    print("\n❌ GUI mode is not available (tkinter not installed)")
                    print("Please install tkinter or use CLI mode instead.\n")
                    input("Press ENTER to continue...")
            
            elif choice == '3':
                # Demo Mode
                demo = DemoMode()
                demo.run()
            
            elif choice == '4':
                # Information
                show_information()
            
            elif choice == '5':
                # Exit
                print("\n" + "═"*76)
                print("  Thank you for using DecodeLabs Password Strength Checker!")
                print("  Stay secure! 🛡️")
                print("═"*76 + "\n")
                break
            
            else:
                print("\n❌ Invalid choice. Please enter 1-5.\n")
                input("Press ENTER to continue...")
        
        except KeyboardInterrupt:
            print("\n\n" + "═"*76)
            print("  Application interrupted. Goodbye!")
            print("═"*76 + "\n")
            break
        except Exception as e:
            print(f"\n❌ An error occurred: {e}\n")
            input("Press ENTER to continue...")


# ═══════════════════════════════════════════════════════════════════════════
# APPLICATION ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    main()

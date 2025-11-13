import streamlit as st
import re
import math
import hashlib
import requests
from typing import Dict, List, Tuple
import time

# Page configuration
st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔑",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .strength-very-weak {
        background: linear-gradient(90deg, #ff4444 0%, #cc0000 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        text-align: center;
    }
    .strength-weak {
        background: linear-gradient(90deg, #ff8800 0%, #ff6600 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        text-align: center;
    }
    .strength-medium {
        background: linear-gradient(90deg, #ffbb33 0%, #ff9900 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        text-align: center;
    }
    .strength-strong {
        background: linear-gradient(90deg, #99cc00 0%, #669900 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        text-align: center;
    }
    .strength-very-strong {
        background: linear-gradient(90deg, #00cc66 0%, #009944 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        text-align: center;
    }
    .metric-card {
        background: #f0f2f6;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #4CAF50;
    }
    .warning-card {
        background: #fff3cd;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #ffc107;
    }
    .success-card {
        background: #d4edda;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #28a745;
    }
    .progress-bar {
        height: 30px;
        border-radius: 15px;
        overflow: hidden;
        background: #e0e0e0;
    }
    </style>
""", unsafe_allow_html=True)

class PasswordAnalyzer:
    """Advanced password strength analyzer"""
    
    # Common weak passwords list
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 
        '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
        'master', 'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow',
        'superman', '123123', 'admin', 'welcome', 'login', 'password1'
    ]
    
    COMMON_PATTERNS = [
        r'12345', r'qwerty', r'asdfg', r'abcde', r'password', 
        r'admin', r'user', r'root', r'test'
    ]
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 33
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    @staticmethod
    def check_character_variety(password: str) -> Dict[str, bool]:
        """Check different character types"""
        return {
            'lowercase': bool(re.search(r'[a-z]', password)),
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'numbers': bool(re.search(r'[0-9]', password)),
            'special': bool(re.search(r'[^a-zA-Z0-9]', password))
        }
    
    @staticmethod
    def check_common_patterns(password: str) -> List[str]:
        """Check for common weak patterns"""
        found_patterns = []
        password_lower = password.lower()
        
        # Check common passwords
        if password_lower in PasswordAnalyzer.COMMON_PASSWORDS:
            found_patterns.append("Common password detected")
        
        # Check sequential patterns
        for pattern in PasswordAnalyzer.COMMON_PATTERNS:
            if re.search(pattern, password_lower):
                found_patterns.append(f"Contains pattern: {pattern}")
        
        # Check keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn']
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                found_patterns.append(f"Keyboard pattern: {pattern}")
        
        # Check repetitive characters
        if re.search(r'(.)\1{2,}', password):
            found_patterns.append("Repetitive characters (e.g., aaa, 111)")
        
        # Check sequential numbers
        if re.search(r'(012|123|234|345|456|567|678|789)', password):
            found_patterns.append("Sequential numbers")
        
        return found_patterns
    
    @staticmethod
    def estimate_crack_time(entropy: float) -> Tuple[str, str]:
        """Estimate time to crack password"""
        # Assuming 1 billion attempts per second
        attempts_per_second = 1e9
        combinations = 2 ** entropy
        seconds = combinations / attempts_per_second
        
        if seconds < 1:
            return "Instant", "danger"
        elif seconds < 60:
            return f"{int(seconds)} seconds", "danger"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes", "warning"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours", "warning"
        elif seconds < 2592000:
            return f"{int(seconds/86400)} days", "info"
        elif seconds < 31536000:
            return f"{int(seconds/2592000)} months", "info"
        else:
            years = int(seconds/31536000)
            if years > 1e6:
                return f"{years/1e6:.1f} million years", "success"
            elif years > 1000:
                return f"{years/1000:.1f} thousand years", "success"
            else:
                return f"{years} years", "success"
    
    @staticmethod
    def calculate_strength_score(password: str) -> Dict:
        """Calculate comprehensive password strength score"""
        score = 0
        max_score = 100
        feedback = []
        
        # Length scoring (0-30 points)
        length = len(password)
        if length >= 16:
            score += 30
            feedback.append("✅ Excellent length (16+ characters)")
        elif length >= 12:
            score += 25
            feedback.append("✅ Good length (12-15 characters)")
        elif length >= 8:
            score += 15
            feedback.append("⚠️ Minimum length (8-11 characters)")
        else:
            score += 5
            feedback.append("❌ Too short (less than 8 characters)")
        
        # Character variety (0-30 points)
        char_types = PasswordAnalyzer.check_character_variety(password)
        variety_count = sum(char_types.values())
        
        if variety_count == 4:
            score += 30
            feedback.append("✅ All character types used")
        elif variety_count == 3:
            score += 20
            feedback.append("⚠️ Missing one character type")
        elif variety_count == 2:
            score += 10
            feedback.append("⚠️ Only two character types")
        else:
            score += 5
            feedback.append("❌ Very limited character variety")
        
        # Entropy scoring (0-25 points)
        entropy = PasswordAnalyzer.calculate_entropy(password)
        if entropy >= 80:
            score += 25
            feedback.append("✅ Very high entropy")
        elif entropy >= 60:
            score += 20
            feedback.append("✅ High entropy")
        elif entropy >= 40:
            score += 15
            feedback.append("⚠️ Moderate entropy")
        else:
            score += 5
            feedback.append("❌ Low entropy")
        
        # Pattern check (0-15 points)
        patterns = PasswordAnalyzer.check_common_patterns(password)
        if not patterns:
            score += 15
            feedback.append("✅ No common patterns detected")
        else:
            score += 0
            for pattern in patterns:
                feedback.append(f"❌ {pattern}")
        
        # Determine strength level
        if score >= 85:
            strength = "Very Strong"
            color = "very-strong"
        elif score >= 70:
            strength = "Strong"
            color = "strong"
        elif score >= 50:
            strength = "Medium"
            color = "medium"
        elif score >= 30:
            strength = "Weak"
            color = "weak"
        else:
            strength = "Very Weak"
            color = "very-weak"
        
        return {
            'score': score,
            'max_score': max_score,
            'percentage': int((score / max_score) * 100),
            'strength': strength,
            'color': color,
            'feedback': feedback,
            'entropy': entropy,
            'char_types': char_types,
            'patterns': patterns
        }
    
    @staticmethod
    def generate_password(length: int = 16, use_special: bool = True) -> str:
        """Generate a strong random password"""
        import secrets
        import string
        
        chars = string.ascii_letters + string.digits
        if use_special:
            chars += string.punctuation
        
        # Ensure at least one of each type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]
        
        if use_special:
            password.append(secrets.choice(string.punctuation))
        
        # Fill the rest randomly
        password += [secrets.choice(chars) for _ in range(length - len(password))]
        
        # Shuffle
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)


def main():
    st.title("🔑 Advanced Password Strength Analyzer")
    st.markdown("### Analyze and improve your password security")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Tools")
        
        mode = st.radio("Select Mode", ["Analyze Password", "Generate Password"])
        
        st.markdown("---")
        st.markdown("### 📊 Security Metrics")
        st.markdown("""
        - **Entropy**: Randomness measure
        - **Character Variety**: Types used
        - **Pattern Detection**: Common weaknesses
        - **Crack Time**: Brute force estimate
        """)
        
        st.markdown("---")
        st.markdown("### 💡 Password Tips")
        st.markdown("""
        1. Use 12+ characters
        2. Mix upper/lowercase
        3. Include numbers
        4. Add special characters
        5. Avoid common words
        6. Use unique passwords
        """)
    
    if mode == "Analyze Password":
        st.header("🔍 Password Analysis")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            password_input = st.text_input(
                "Enter password to analyze",
                type="password",
                key="password_input",
                help="Your password is analyzed locally and never sent anywhere"
            )
            
            show_password = st.checkbox("👁️ Show password")
            
            if show_password and password_input:
                st.code(password_input, language=None)
            
            if password_input:
                with st.spinner("Analyzing..."):
                    time.sleep(0.3)  # Visual effect
                    
                    result = PasswordAnalyzer.calculate_strength_score(password_input)
                    
                    # Strength indicator
                    st.markdown(f"""
                        <div class="strength-{result['color']}">
                            Password Strength: {result['strength']} ({result['percentage']}%)
                        </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("<br>", unsafe_allow_html=True)
                    
                    # Progress bar
                    st.progress(result['percentage'] / 100)
                    
                    # Metrics
                    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                    
                    with col_m1:
                        st.metric("Length", len(password_input))
                    
                    with col_m2:
                        st.metric("Entropy", f"{result['entropy']} bits")
                    
                    with col_m3:
                        char_variety = sum(result['char_types'].values())
                        st.metric("Char Types", f"{char_variety}/4")
                    
                    with col_m4:
                        crack_time, _ = PasswordAnalyzer.estimate_crack_time(result['entropy'])
                        st.metric("Crack Time", crack_time)
                    
                    st.markdown("<br>", unsafe_allow_html=True)
                    
                    # Character types
                    st.subheader("📝 Character Analysis")
                    char_cols = st.columns(4)
                    
                    char_labels = {
                        'lowercase': 'Lowercase (a-z)',
                        'uppercase': 'Uppercase (A-Z)',
                        'numbers': 'Numbers (0-9)',
                        'special': 'Special (!@#$...)'
                    }
                    
                    for idx, (key, value) in enumerate(result['char_types'].items()):
                        with char_cols[idx]:
                            if value:
                                st.success(f"✅ {char_labels[key]}")
                            else:
                                st.error(f"❌ {char_labels[key]}")
                    
                    # Feedback
                    st.subheader("💬 Detailed Feedback")
                    for item in result['feedback']:
                        if '✅' in item:
                            st.success(item)
                        elif '⚠️' in item:
                            st.warning(item)
                        else:
                            st.error(item)
                    
                    # Recommendations
                    if result['percentage'] < 70:
                        st.subheader("🎯 Recommendations")
                        
                        recommendations = []
                        
                        if len(password_input) < 12:
                            recommendations.append("Increase length to at least 12 characters")
                        
                        if not result['char_types']['uppercase']:
                            recommendations.append("Add uppercase letters")
                        
                        if not result['char_types']['lowercase']:
                            recommendations.append("Add lowercase letters")
                        
                        if not result['char_types']['numbers']:
                            recommendations.append("Add numbers")
                        
                        if not result['char_types']['special']:
                            recommendations.append("Add special characters (!@#$%^&*)")
                        
                        if result['patterns']:
                            recommendations.append("Avoid common patterns and words")
                        
                        for rec in recommendations:
                            st.info(f"💡 {rec}")
        
        with col2:
            if password_input:
                st.markdown("### 📈 Score Breakdown")
                
                st.markdown(f"""
                    <div class="metric-card">
                        <h4>Total Score</h4>
                        <h2>{result['score']}/{result['max_score']}</h2>
                    </div>
                """, unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # Visual score representation
                score_data = {
                    'Length': min(30, (len(password_input) / 16) * 30),
                    'Variety': sum(result['char_types'].values()) * 7.5,
                    'Entropy': min(25, (result['entropy'] / 80) * 25),
                    'Patterns': 15 if not result['patterns'] else 0
                }
                
                for category, points in score_data.items():
                    st.markdown(f"**{category}**: {int(points)}/30-25")
                    st.progress(points / 30)
    
    else:  # Generate Password
        st.header("🎲 Password Generator")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            length = st.slider("Password Length", 8, 32, 16)
            use_special = st.checkbox("Include Special Characters", value=True)
            
            if st.button("🎲 Generate Strong Password", type="primary"):
                generated_password = PasswordAnalyzer.generate_password(length, use_special)
                
                st.success("✅ Password generated successfully!")
                
                st.subheader("🔑 Your New Password")
                st.code(generated_password, language=None)
                
                # Analyze generated password
                result = PasswordAnalyzer.calculate_strength_score(generated_password)
                
                st.markdown(f"""
                    <div class="strength-{result['color']}">
                        Strength: {result['strength']} ({result['percentage']}%)
                    </div>
                """, unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                col_g1, col_g2, col_g3 = st.columns(3)
                
                with col_g1:
                    st.metric("Length", len(generated_password))
                
                with col_g2:
                    st.metric("Entropy", f"{result['entropy']} bits")
                
                with col_g3:
                    crack_time, _ = PasswordAnalyzer.estimate_crack_time(result['entropy'])
                    st.metric("Crack Time", crack_time)
                
                st.info("💡 Copy this password and store it securely in a password manager")
        
        with col2:
            st.markdown("### ℹ️ Generator Info")
            st.markdown("""
                **Features:**
                - Cryptographically secure
                - Random generation
                - Customizable length
                - Optional special chars
                
                **Best Practices:**
                - Use 16+ characters
                - Enable special chars
                - Store in password manager
                - Never reuse passwords
            """)
    
    # Footer
    st.markdown("---")
    st.markdown("""
        <div style='text-align: center; color: #666;'>
            🔒 All analysis is performed locally in your browser. Your passwords are never sent or stored anywhere.
        </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import re

class ThreatDetector:
    def __init__(self):
        print("🤖 Initializing Threat Detector...")
        
        # Load Kaggle dataset
        try:
            self.df = pd.read_csv("spam.csv", encoding='latin-1')
            print(f"✅ Dataset loaded: {len(self.df)} rows")
            
            self.df = self.df[['v1', 'v2']].copy()
            self.df.columns = ['label', 'text']
            
            print(f"\n📊 Label counts: {self.df['label'].value_counts().to_dict()}")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            self.df = pd.DataFrame({
                'label': ['ham', 'spam', 'ham', 'spam'],
                'text': ['Hello', 'Free money', 'Meeting', 'Click here']
            })
        
        # Load test samples
        try:
            from test_samples import TEST_SAMPLES
            self.test_samples = [sample[0] for sample in TEST_SAMPLES]
            print(f"✅ Loaded {len(self.test_samples)} test samples")
        except ImportError as e:
            print(f"⚠️ Test samples not found: {e}")
            self.test_samples = []
        
        # Keyword definitions - COMPLETE UPDATED
        self.keywords = {
            'phishing': [
                'verify', 'account', 'click', 'link', 'urgent', 'password', 
                'login', 'suspended', 'update', 'confirm', 'secure', 
                'action required', 'http://', 'https://', 'bit.ly', 'paypal',
                'payment failed', 'payment issue', 'billing', 'subscription',
                'netflix', 'amazon', 'spotify', 'apple', 'google', 'microsoft',
                'facebook', 'instagram', 'whatsapp', 'twitter', 'youtube',
                'expired', 'overdue', 'charge', 'card declined', 'failed payment',
                'payment method', 'renew', 'restore', 'reactivate', 'locked out',
                'immediately', 'asap', 'required', 'must', 'need to', 'now',
                'notification', 'alert', 'warning', 'important', 'attention',
                'suspicious activity', 'unusual login', 'security alert',
                'hacked', 'compromised', 'verify identity', 'confirm details'
            ],
            
            'scam': [
                'free', 'win', 'won', 'prize', 'lottery', 'money', 'cash',
                'winner', 'congratulations', 'award', 'bonus', 'reward',
                'million', 'billion', 'guaranteed', 'claim', 'earn',
                'limited time', 'exclusive offer', 'special deal', 'only today',
                'discount', 'coupon', 'voucher', 'giveaway', 'free gift',
                'earn money', 'make money', 'quick cash', 'easy money',
                'investment', 'crypto', 'bitcoin', 'stock', 'trading',
                'work from home', 'no experience', 'part time', 'full time',
                'dm me', 'message me', 'contact me', 'whatsapp me', 'call me',
                'send details', 'share bank', 'transfer money', 'quick loan',
                'get rich', 'instant cash', 'passive income'
            ],
            
            'harassment': [
                'kill', 'hurt', 'die', 'hate', 'stupid', 'ugly', 'fat',
                'worthless', 'garbage', 'bastard', 'idiot', 'moron',
                'retard', 'suicide', 'destroy', 'nobody wants',
                'useless', 'dumb', 'fool', 'shut up', 'leave me',
                'stop talking', 'threaten', 'bully', 'harass', 'stalk',
                'creep', 'weirdo', 'hate you', 'despise', 'loathe'
            ],
            
            'malware': [
                '.exe', '.scr', '.bat', '.cmd', '.msi', '.jar',
                'download', 'install', 'attachment', 'open file',
                'virus', 'trojan', 'malware', 'ransomware', 'spyware',
                'keylogger', 'adware', 'worm', 'hack tool', 'crack',
                'free software', 'cracked', 'nulled', 'pirated',
                'update file', 'security patch', 'driver update',
                '[.]exe', '[.]scr', '[.]bat', '[.]cmd',
                'doc.exe', 'invoice.exe', 'view.exe', 'open.exe',
                'document.exe', 'file.exe', 'video.exe', 'photo.exe'
            ],
            
            'fraud': [
                'ssn', 'social security', 'credit card', 'bank details',
                'password', 'pin', 'otp', 'verify identity', 'card number',
                'personal information', 'id verification', 'date of birth',
                'mother maiden name', 'security question', 'security answer',
                'atm pin', 'cvv', 'expiry date', 'bank account', 'routing number',
                'wire transfer', 'send money', 'western union', 'moneygram',
                'refund', 'tax refund', 'irs', 'government grant', 'inheritance',
                'account number', 'sort code', 'swift code', 'iban'
            ]
        }
        
        # ML Setup
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        
        # Train model
        self.train_model()
        
        print("✅ Threat Detector initialized!")
    
    def train_model(self):
        """Train ML model for spam/ham detection only"""
        print("\n📚 Training ML model...")
        
        X = self.df['text'].fillna('').astype(str)
        y = self.df['label'].apply(lambda x: 1 if str(x).strip().lower() == 'spam' else 0)
        
        X_vectorized = self.vectorizer.fit_transform(X)
        self.model.fit(X_vectorized, y)
        
        train_acc = self.model.score(X_vectorized, y)
        print(f"✅ Trained on {len(X)} samples")
        print(f"   Accuracy: {train_acc:.1%}")
        print(f"   Spam: {sum(y)}, Ham: {len(y)-sum(y)}")
    
    def analyze(self, text: str) -> dict:
        """Main analysis function - FINAL WORKING VERSION"""
        if not text or not isinstance(text, str):
            return self._error_response("Invalid input")
        
        text = str(text).strip()
        text_lower = text.lower()
        
        # STEP 1: Detect category using keywords
        final_category = self._detect_category(text_lower)
        
        # STEP 2: ML prediction
        ml_is_spam, ml_confidence = self._ml_predict(text)
        
        # STEP 3: If ML says spam but no specific category, default to phishing
        if ml_is_spam and final_category == 'safe':
            final_category = 'phishing'
        
        # STEP 4: Calculate scores
        risk_score = self._calculate_risk(final_category, text_lower)
        confidence = self._calculate_confidence(final_category, ml_confidence)
        
        # STEP 5: Get found keywords
        found_keywords = self._get_keywords_found(text_lower, final_category)
        
        # STEP 6: Generate explanation
        explanation = self._generate_explanation(final_category, found_keywords, text_lower)
        
        return {
            "threat_category": final_category,
            "risk_score": risk_score,
            "confidence": round(confidence, 1),
            "explanation": explanation,
            "keywords_found": found_keywords
        }
    
    def _detect_category(self, text_lower: str) -> str:
        """Detect threat category - COMPLETE IMPROVED VERSION"""
        
        # Check multi-word phrases first (most specific)
        if 'payment failed' in text_lower or 'card declined' in text_lower:
            return 'phishing'
        if 'social security' in text_lower:
            return 'fraud'
        
        # Check for harassment first (most serious)
        harassment_words = ['kill', 'hurt', 'die', 'hate', 'worthless', 'garbage', 'stupid', 'idiot']
        if any(word in text_lower for word in harassment_words):
            return 'harassment'
        
        # Check for malware - FIXED with bracket support
        malware_indicators = ['.exe', '.scr', '.bat', '[.]exe', '[.]scr', '[.]bat']
        if any(indicator in text_lower for indicator in malware_indicators):
            return 'malware'
        
        # Check for fraud
        fraud_words = ['ssn', 'credit card', 'bank details', 'card number', 'routing number']
        if any(word in text_lower for word in fraud_words):
            return 'fraud'
        
        # Check for phishing - COMPLETE
        phishing_words = [
            'verify', 'account', 'click', 'login', 'password', 'urgent', 
            'suspended', 'verification', 'code', 'locked out', 'recovery',
            'send me', 'whatsapp code', 'fb code', 'facebook', 'instagram',
            'help me', 'cant access', 'restore', 'account recovery',
            'payment issue', 'billing', 'subscription', 'netflix',
            'amazon', 'spotify', 'paypal', 'expired', 'overdue',
            'immediately', 'asap', 'required', 'notification', 'alert',
            'security alert', 'unusual login', 'hacked', 'compromised'
        ]
        if any(word in text_lower for word in phishing_words):
            return 'phishing'
        
        # Check for scam - COMPLETE
        scam_words = [
            'won', 'prize', 'free', 'lottery', 'money', 'cash', 'winner',
            'earn', 'daily', 'weekly', 'monthly', 'income', 'salary',
            'work from home', 'no experience', 'guaranteed', 'investment',
            'profit', 'rich', 'wealth', 'financial freedom', 'dm for',
            'message for', 'contact for', 'whatsapp for', 'call for',
            'limited time', 'exclusive', 'special', 'discount', 'coupon',
            'earn money', 'make money', 'quick cash', 'investment',
            'get rich', 'instant cash', 'passive income'
        ]
        if any(word in text_lower for word in scam_words):
            return 'scam'
        
        # Default to safe
        return 'safe'
    
    def _ml_predict(self, text: str):
        """ML prediction"""
        try:
            text_vec = self.vectorizer.transform([text])
            proba = self.model.predict_proba(text_vec)[0]
            
            spam_prob = proba[1] if len(proba) > 1 else 0.5
            return spam_prob > 0.5, max(spam_prob, 1 - spam_prob)
        except:
            return False, 0.5
    
    def _calculate_risk(self, category: str, text_lower: str) -> int:
        """Calculate risk score 0-100"""
        base_scores = {
            'harassment': 95,
            'malware': 90,
            'fraud': 85,
            'phishing': 80,
            'scam': 75,
            'safe': 10
        }
        
        score = base_scores.get(category, 50)
        
        # Bonus for specific indicators
        if 'http' in text_lower or 'https://' in text_lower:
            score += 20
        if 'urgent' in text_lower or 'immediate' in text_lower or 'asap' in text_lower:
            score += 15
        if '$' in text_lower:
            score += 10
        if '.exe' in text_lower or '.scr' in text_lower or '[.]exe' in text_lower:
            score += 25
        
        return min(100, score)
    
    def _calculate_confidence(self, category: str, ml_confidence: float) -> float:
        """Calculate confidence %"""
        if category == 'safe':
            return ml_confidence * 100
        else:
            return 70 + (ml_confidence * 30)  # Boost for threats
    
    def _get_keywords_found(self, text_lower: str, category: str) -> list:
        """Get found keywords"""
        if category == 'safe':
            return []
        
        found = []
        for keyword in self.keywords.get(category, []):
            if keyword in text_lower:
                found.append(keyword)
        
        return found[:3]  # Return first 3
    
    def _generate_explanation(self, category: str, found_keywords: list, text_lower: str) -> str:
        """Generate explanation"""
        if category == 'safe':
            return "✅ No threats detected. This message appears safe."
        
        # Get threat-specific message
        messages = {
            'phishing': "Attempts to steal credentials through deceptive links or requests.",
            'scam': "Fraudulent offer that seems too good to be true.",
            'harassment': "Contains harmful, abusive, or threatening language.",
            'malware': "Attempts to distribute malicious software or files.",
            'fraud': "Attempts to obtain personal/financial information illegally."
        }
        
        threat_msg = messages.get(category, "Potential security threat detected.")
        
        if found_keywords:
            keywords_str = ", ".join(f"'{kw}'" for kw in found_keywords)
            return f"⚠️ **{category.upper()} DETECTED** - {threat_msg} Found indicators: {keywords_str}."
        else:
            return f"⚠️ **{category.upper()} DETECTED** - {threat_msg}"
    
    def _error_response(self, error_msg: str) -> dict:
        return {
            "threat_category": "error",
            "risk_score": 0,
            "confidence": 0,
            "explanation": f"Error: {error_msg}",
            "keywords_found": []
        }

# Quick test
if __name__ == "__main__":
    detector = ThreatDetector()
    
    print("\n🔍 Testing with sample messages:")
    test_msgs = [
        "Verify your bank account now",
        "You won $1000 prize",
        "I will hurt you",
        "Download invoice.exe",
        "Doc ready: view-doc[.]exe",
        "Your SSN needs verification",
        "Netflix: payment failed. Update now",
        "Package arrived. Sign: deliver-now.link",
        "Bank: unusual login. Verify: secure-bank[.]com",
        "Free iPhone giveaway! Join: apple-gift[.]com",
        "Hello how are you",
        "Meeting at 3pm tomorrow"
    ]
    
    for msg in test_msgs:
        result = detector.analyze(msg)
        print(f"\n📩 '{msg}'")
        print(f"   Category: {result['threat_category'].upper()}")
        print(f"   Risk: {result['risk_score']}/100")
        print(f"   Confidence: {result['confidence']}%")

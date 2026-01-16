from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn
import os
from controller import ThreatDetector

# Get the absolute path to frontend folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

# Initialize your threat detector
detector = ThreatDetector()

# Create FastAPI app
app = FastAPI(
    title="Cyber Threat Detection API",
    description="Detect phishing, scams, harassment, malware, fraud in text messages",
    version="1.0.0"
)

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define request model
class TextRequest(BaseModel):
    text: str

# ==================== ROUTES ====================

@app.get("/")
def serve_dashboard():
    """Serve the HTML dashboard from frontend folder"""
    html_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    else:
        return {"error": f"index.html not found at: {html_path}"}

@app.post("/analyze")
def analyze_text_post(request: TextRequest):
    """Analyze text using POST request with JSON"""
    try:
        if not request.text or len(request.text.strip()) == 0:
            raise HTTPException(status_code=400, detail="Text cannot be empty")
        
        result = detector.analyze(request.text)
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

@app.get("/analyze")
def analyze_text_get(text: str):
    """Analyze text using GET request with URL parameter"""
    try:
        if not text or len(text.strip()) == 0:
            raise HTTPException(status_code=400, detail="Text cannot be empty")
        
        result = detector.analyze(text)
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

@app.get("/test")
def test_samples():
    """Test the API with sample messages from test_samples.py"""
    try:
        from test_samples import TEST_SAMPLES
        samples = [sample[0] for sample in TEST_SAMPLES]  # Extract just text
        
        results = []
        for sample in samples:
            result = detector.analyze(sample)
            results.append({
                "input": sample,
                "result": result
            })
        
        return {
            "total_tested": len(results),
            "samples": results
        }
    except ImportError:
        return {"error": "test_samples.py not found"}

@app.get("/test-advanced")
def test_advanced():
    """Test with both text and expected category"""
    try:
        from test_samples import TEST_SAMPLES
        
        results = []
        correct = 0
        
        for text, expected_category in TEST_SAMPLES:
            result = detector.analyze(text)
            detected_category = result["threat_category"]
            is_correct = detected_category == expected_category
            
            if is_correct:
                correct += 1
            
            results.append({
                "text": text,
                "expected": expected_category,
                "detected": detected_category,
                "correct": is_correct,
                "risk_score": result["risk_score"],
                "confidence": result["confidence"]
            })
        
        accuracy = (correct / len(TEST_SAMPLES)) * 100
        
        return {
            "total_tests": len(TEST_SAMPLES),
            "correct": correct,
            "incorrect": len(TEST_SAMPLES) - correct,
            "accuracy": f"{accuracy:.1f}%",
            "breakdown": results
        }
    except ImportError:
        return {"error": "test_samples.py not found"}

@app.get("/stats")
def get_stats():
    """Get API statistics"""
    return {
        "status": "running",
        "model_trained": True,
        "training_samples": len(detector.df),
        "spam_count": len(detector.df[detector.df['label'] == 'spam']),
        "ham_count": len(detector.df[detector.df['label'] == 'ham']),
        "test_samples_available": len(detector.test_samples) if hasattr(detector, 'test_samples') else 0
    }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "Threat Detection API"}

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 CYBER THREAT DETECTION SYSTEM")
    print("=" * 60)
    print("📡 Dashboard: http://localhost:8000")
    print("🔗 Test API: http://localhost:8000/analyze?text=hello")
    print("🧪 Advanced Test: http://localhost:8000/test-advanced")
    print("📊 Stats: http://localhost:8000/stats")
    print("📚 API Docs: http://localhost:8000/docs")
    print("=" * 60)
    print("📁 Folder structure:")
    print(f"   Backend: {BASE_DIR}")
    print(f"   Frontend: {FRONTEND_DIR}")
    print("=" * 60)
    
    # Check if files exist
    if os.path.exists(os.path.join(FRONTEND_DIR, "index.html")):
        print("✅ index.html found in frontend folder")
    else:
        print("❌ index.html NOT found in frontend folder")
    
    if os.path.exists(os.path.join(BASE_DIR, "spam.csv")):
        print("✅ spam.csv dataset found")
    else:
        print("⚠️ spam.csv not found, using sample data")
    
    print("=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)

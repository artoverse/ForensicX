"""LLM service module for optional Phi-3 integration"""
from .config import USE_LLM, MODEL_PATH

class LLMService:
    """Wrapper for llama-cpp-python LLM inference"""
    
    def __init__(self):
        self.available = False
        self.model = None
        
        if USE_LLM:
            try:
                from llama_cpp import Llama
                print(f"[LLM] Loading model from {MODEL_PATH}")
                self.model = Llama(
                    model_path=str(MODEL_PATH),
                    n_ctx=2048,
                    n_threads=4,
                    n_gpu_layers=0  # Use CPU; set > 0 for GPU
                )
                self.available = True
                print("[LLM] Model loaded successfully")
            except ImportError:
                print("[LLM] llama-cpp-python not installed; LLM disabled")
            except Exception as e:
                print(f"[LLM] Failed to load model: {e}")
    
    def generate_insights(self, analysis_summary):
        """Generate insights from analysis using LLM"""
        if not self.available or not self.model:
            return None
        
        try:
            prompt = f"""Based on this security analysis:
{analysis_summary}

Provide 3 key security insights and 2 recommended actions:"""
            
            response = self.model(
                prompt,
                max_tokens=200,
                temperature=0.7,
                top_p=0.9,
                echo=False
            )
            
            return response['choices'][0]['text'].strip()
        except Exception as e:
            print(f"[LLM] Error generating insights: {e}")
            return None
    
    def answer_question(self, question, context):
        """Answer user question about analysis"""
        if not self.available or not self.model:
            return None
        
        try:
            prompt = f"""Context: {context}

Question: {question}

Answer concisely:"""
            
            response = self.model(
                prompt,
                max_tokens=150,
                temperature=0.7,
                top_p=0.9,
                echo=False
            )
            
            return response['choices'][0]['text'].strip()
        except Exception as e:
            print(f"[LLM] Error answering question: {e}")
            return None

# Initialize LLM service
llm_service = LLMService()
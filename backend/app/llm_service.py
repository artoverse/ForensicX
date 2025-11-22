"""
ðŸ”¥ ENHANCED LLM SERVICE - Comprehensive Detection
Prompts LLM to find 30+ incidents like ChatGPT
"""

from .config import USE_LLM, MODEL_PATH
import json
import re
from collections import Counter
from datetime import datetime

class LLMService:
    """Enhanced LLM service for comprehensive threat detection"""
    
    def __init__(self):
        self.available = False
        self.model = None
        
        if not USE_LLM:
            print("ðŸ”§ LLM disabled in config")
            return
        
        try:
            from llama_cpp import Llama
            
            if not MODEL_PATH or not MODEL_PATH.exists():
                print(f"âŒ Model not found at: {MODEL_PATH}")
                return
            
            print(f"\n{'='*70}")
            print(f"ðŸ¤– Loading Mistral for COMPREHENSIVE analysis...")
            print(f"ðŸ“ {MODEL_PATH.name}")
            print(f"{'='*70}\n")
            
            self.model = Llama(
                model_path=str(MODEL_PATH),
                n_ctx=4096,         # Larger context for better analysis
                n_threads=4,
                n_batch=256,
                n_gpu_layers=0,
                verbose=False
            )
            
            self.available = True
            print("âœ… Model loaded - ready for deep analysis\n")
            
        except ImportError:
            print("âŒ llama-cpp-python not installed")
        except Exception as e:
            print(f"âŒ Model load failed: {e}\n")
    
    def analyze_logs_complete(self, filename, log_sample, total_lines):
        """
        COMPREHENSIVE log analysis - find ALL threats
        Returns: (incidents, file_metrics, summary, iocs, recommendations)
        """
        if not self.available:
            return None
        
        try:
            # Enhanced prompt for comprehensive detection
            prompt = f"""[INST] You are an elite cybersecurity forensic analyst with 20 years of experience. Analyze these security logs with EXTREME thoroughness.

**FILE:** {filename}
**SAMPLE:** {len(log_sample.splitlines())}/{total_lines} lines

**LOG SAMPLE:**
{log_sample[:3000]}

**YOUR MISSION:** Find EVERY security threat, anomaly, and suspicious pattern. Be thorough like a real forensic analyst.

**ANALYZE FOR:**
1. **Authentication**: Failed logins, brute force, compromised accounts, lockouts
2. **Network**: Suspicious ports (4444, 3389, 31337), port scans, C2 traffic
3. **Malware**: Ransomware, trojans, backdoors, exploit tools (Metasploit, Mimikatz)
4. **Data**: Exfiltration, large transfers, SQL injection, data theft
5. **System**: Privilege escalation, command execution, registry changes
6. **Lateral Movement**: Pass-the-hash, PSExec, credential theft
7. **Persistence**: Scheduled tasks, startup items, service installs
8. **Web Attacks**: XSS, SQL injection, file inclusion
9. **Reconnaissance**: Scanning, enumeration, discovery
10. **APT Indicators**: Advanced techniques, sophisticated attacks

**OUTPUT FORMAT (JSON only):**
{{
  "incidents": [
    {{"type": "Specific_Threat_Name", "severity": "critical|high|medium|low", "confidence": 85, "detail": "What happened, evidence, impact"}},
    {{"type": "Another_Threat", "severity": "high", "confidence": 90, "detail": "Detailed description with context"}}
  ],
  "iocs": ["IP:1.2.3.4", "Port:4444", "Domain:malicious.com", "Hash:abc123..."],
  "recommendations": [
    "Immediate action 1 with specific IPs/ports/systems",
    "Specific action 2 based on findings",
    "Detailed step 3 with technical details"
  ]
}}

**CRITICAL REQUIREMENTS:**
- Find AT LEAST 15-30 incidents if threats exist
- Every incident needs specific evidence and impact
- Confidence must be 70-100 based on evidence strength
- Recommendations must be actionable and specific (include IPs, ports, etc.)
- Look for patterns, correlations, sequences
- Consider what attackers do: scan â†’ exploit â†’ escalate â†’ persist â†’ exfiltrate

**OUTPUT JSON ONLY - NO EXPLANATION TEXT:**
[/INST]"""
            
            print(f"ðŸ¤– LLM performing deep analysis...")
            
            # Generate with more tokens for comprehensive results
            response = self.model(
                prompt,
                max_tokens=2000,     # Much more tokens for comprehensive results
                temperature=0.3,     # Balanced creativity
                top_p=0.9,
                repeat_penalty=1.1,
                stop=["[INST]", "</s>", "[/INST]"]
            )
            
            output = response['choices'][0]['text'].strip()
            print(f"ðŸ“Š Generated {len(output)} chars")
            
            # Parse
            return self._parse_comprehensive_output(output, total_lines)
        
        except Exception as e:
            print(f"âŒ LLM error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _parse_comprehensive_output(self, output, total_lines):
        """Parse LLM output into 5-tuple"""
        try:
            # Extract JSON (handle various formats)
            json_match = re.search(r'\{[\s\S]*\}', output)
            if not json_match:
                print("âš ï¸  No JSON in output")
                return None
            
            json_str = json_match.group(0)
            
            # Clean up common JSON issues
            json_str = json_str.replace('\n', ' ')
            json_str = re.sub(r',\s*}', '}', json_str)
            json_str = re.sub(r',\s*]', ']', json_str)
            
            data = json.loads(json_str)
            
            incidents = data.get('incidents', [])
            iocs = data.get('iocs', [])
            recommendations = data.get('recommendations', [])
            
            # Validate and fix incidents
            for inc in incidents:
                if 'confidence' not in inc:
                    inc['confidence'] = 80
                if 'severity' not in inc:
                    inc['severity'] = 'medium'
                if 'type' not in inc:
                    inc['type'] = 'Unknown_Threat'
                if 'detail' not in inc:
                    inc['detail'] = 'Security incident detected'
            
            # Build metrics
            severity_count = Counter()
            for inc in incidents:
                severity_count[inc.get('severity', 'medium')] += 1
            
            file_metrics = {
                'events_count': total_lines,
                'critical_count': severity_count.get('critical', 0),
                'high_count': severity_count.get('high', 0),
                'medium_count': severity_count.get('medium', 0),
                'low_count': severity_count.get('low', 0),
                'total_incidents': len(incidents),
                'ioc_count': len(iocs)
            }
            
            summary = {
                'file': 'analyzed',
                'lines': total_lines,
                'analysis_time': 0,
                'incident_count': len(incidents),
                'timestamp': datetime.now().isoformat()
            }
            
            print(f"âœ… Parsed: {len(incidents)} incidents, {len(iocs)} IOCs, {len(recommendations)} recommendations")
            print(f"   ðŸ”´ Critical: {severity_count.get('critical', 0)}")
            print(f"   ðŸŸ  High: {severity_count.get('high', 0)}")
            print(f"   ðŸŸ¡ Medium: {severity_count.get('medium', 0)}")
            
            return (incidents, file_metrics, summary, iocs, recommendations)
        
        except json.JSONDecodeError as e:
            print(f"âš ï¸  JSON parse error: {e}")
            print(f"Output preview: {output[:300]}...")
            return None
        except Exception as e:
            print(f"âŒ Parse error: {e}")
            return None
    
    def answer_question(self, question, analysis_data):
        """Enhanced Q&A with better context"""
        if not self.available:
            return None
        
        try:
            metrics = analysis_data.get('file_metrics', {})
            incidents = analysis_data.get('incidents', [])[:15]
            
            context = f"""**FORENSIC ANALYSIS SUMMARY:**
File: {analysis_data.get('filename', 'Unknown')}
Total Events: {metrics.get('events_count', 0)}
Incidents: {metrics.get('total_incidents', 0)} ({metrics.get('critical_count', 0)} critical, {metrics.get('high_count', 0)} high)

**TOP INCIDENTS:**
"""
            for i, inc in enumerate(incidents, 1):
                context += f"{i}. [{inc.get('severity', '?').upper()}] {inc.get('type', 'Unknown')} (Confidence: {inc.get('confidence', 'N/A')}%)\n"
                context += f"   {inc.get('detail', 'No details')[:80]}...\n"
            
            prompt = f"""[INST] You are a cybersecurity forensic expert answering questions about a security analysis.

{context}

**Question:** {question}

**Instructions:** 
- Provide expert-level answer (150-200 words)
- Reference specific incidents from the analysis
- Include technical details and forensic context
- Explain attack techniques and implications
- Suggest specific investigative steps

**Answer:**
[/INST]"""
            
            response = self.model(
                prompt,
                max_tokens=400,
                temperature=0.6,
                top_p=0.95
            )
            
            answer = response['choices'][0]['text'].strip()
            
            if len(answer) > 50:
                return answer
        
        except Exception as e:
            print(f"âŒ Chat error: {e}")
        
        return None


# Initialize
llm_service = LLMService()
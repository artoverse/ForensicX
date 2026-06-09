"""
🚀 ForensicX LLM Service — HuggingFace Inference API
Replaces local llama_cpp GGUF model with a hosted remote LLM.
Uses: mistralai/Mistral-7B-Instruct-v0.3 (free HuggingFace Inference API)
"""
import json
import re
import time
from collections import Counter
from datetime import datetime

from .config import USE_LLM, HF_TOKEN, HF_MODEL


class LLMService:
    """LLM service powered by HuggingFace Inference API (no local model needed)"""

    def __init__(self):
        self.available = False
        self.client = None
        self.model = HF_MODEL
        self.model_label = HF_MODEL.split('/')[-1]  # e.g. "Meta-Llama-3-8B-Instruct"

        if not USE_LLM:
            print("⚠️  LLM disabled — set HF_TOKEN in .env to enable AI analysis")
            return

        try:
            from huggingface_hub import InferenceClient

            self.client = InferenceClient(
                model=self.model,
                token=HF_TOKEN,
                timeout=60,
            )
            # ── Real connectivity test: send a tiny prompt to confirm the model works ──
            print(f"🔍 Testing HuggingFace connection to {self.model}...")
            test_resp = self.client.chat_completion(
                messages=[{"role": "user", "content": "Reply with one word: ready"}],
                max_tokens=10,
            )
            if test_resp and test_resp.choices:
                self.available = True
                print(f"✅ HuggingFace LLM ready: {self.model}")
            else:
                print("❌ HuggingFace API returned empty test response")

        except ImportError:
            print("❌ huggingface_hub not installed — run: pip install huggingface_hub")
        except Exception as e:
            print(f"❌ HuggingFace connection test failed: {e}")

    # -------------------------------------------------------------------------
    # Internal: Call the HF Inference API
    # -------------------------------------------------------------------------

    def _call_api(self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1) -> str | None:
        """
        Send a prompt to HuggingFace Inference API and return the response text.
        Returns None on failure.
        """
        if not self.client:
            return None

        try:
            messages = [{"role": "user", "content": prompt}]

            response = self.client.chat_completion(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content.strip()

        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "rate limit" in err_str.lower():
                print("⚠️  HF rate limit hit — waiting 10s and retrying...")
                time.sleep(10)
                try:
                    response = self.client.chat_completion(
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )
                    return response.choices[0].message.content.strip()
                except Exception as retry_e:
                    print(f"❌ Retry failed: {retry_e}")
                    return None
            print(f"❌ HF API error: {e}")
            return None

    # -------------------------------------------------------------------------
    # Public: Full log analysis
    # -------------------------------------------------------------------------

    def analyze_logs_complete(self, filename: str, log_sample: str, total_lines: int):
        """
        Comprehensive log analysis via HuggingFace LLM.
        Returns: (incidents, file_metrics, summary, iocs, recommendations) or None
        """
        if not self.available:
            return None

        prompt = (
            "You are an elite cybersecurity forensic analyst. Analyze the following log file "
            "and produce a comprehensive security report in STRICT JSON format.\n\n"
            f"File: {filename}\n"
            f"Sample: {min(len(log_sample.splitlines()), 1800)}/{total_lines} lines\n\n"
            f"LOG SAMPLE:\n{log_sample[:2000]}\n\n"
            "INSTRUCTIONS:\n"
            "1. Identify ALL security threats, anomalies, and suspicious patterns.\n"
            "2. For each incident include: type (specific), severity (critical/high/medium/low), "
            "confidence (0-100), detail (unique English sentence describing this specific finding).\n"
            "3. List all IOCs (indicators of compromise) as strings.\n"
            "4. Provide actionable recommendations as strings.\n"
            "5. Write a 4-6 sentence executive summary covering findings, severity trends, and next steps.\n"
            "6. OUTPUT ONLY VALID JSON — no extra text, no markdown code fences, no comments.\n\n"
            "Required JSON structure:\n"
            "{\n"
            '  "incidents": [{"type": "...", "severity": "...", "confidence": 90, "detail": "..."}, ...],\n'
            '  "iocs": ["string", ...],\n'
            '  "recommendations": ["string", ...],\n'
            '  "summary": "Executive summary text here..."\n'
            "}"
        )

        print(f"🤖 Sending log to HuggingFace LLM ({self.model})...")
        start = time.time()

        output = self._call_api(prompt, max_tokens=2000, temperature=0.1)

        if not output:
            print("❌ No response from HuggingFace API")
            return None

        elapsed = time.time() - start
        print(f"📊 HF response received in {elapsed:.1f}s ({len(output)} chars)")

        parsed = self._parse_analysis_output(output, total_lines, elapsed)
        return parsed

    # -------------------------------------------------------------------------
    # Public: Q&A chat
    # -------------------------------------------------------------------------

    def answer_question(self, question: str, analysis_data: dict, chat_history: list = None) -> str | None:
        """
        Answer a security question about the analyzed log using HuggingFace LLM.
        Falls back to None so chat_manager can use rule-based fallback.
        """
        if not self.available:
            return None

        metrics = analysis_data.get('file_metrics', {})
        incidents = analysis_data.get('incidents', [])[:12]

        context = (
            f"FORENSIC ANALYSIS SUMMARY:\n"
            f"File: {analysis_data.get('filename', 'Unknown')}\n"
            f"Total Events: {metrics.get('events_count', 0)}\n"
            f"Incidents: {metrics.get('total_incidents', 0)} "
            f"({metrics.get('critical_count', 0)} critical, {metrics.get('high_count', 0)} high)\n\n"
            "TOP INCIDENTS:\n"
        )
        for i, inc in enumerate(incidents, 1):
            context += (
                f"{i}. [{inc.get('severity', '?').upper()}] {inc.get('type', 'Unknown')} "
                f"(Confidence: {inc.get('confidence', 'N/A')}%)\n"
                f"   {inc.get('detail', 'No details')[:100]}\n"
            )

        # Include recent conversation context
        conversation_context = ""
        if chat_history:
            recent = chat_history[-6:]
            conversation_context = "\nPREVIOUS CONVERSATION:\n"
            for msg in recent:
                role = msg.get('role', 'unknown').upper()
                content = msg.get('content', '')[:150]
                conversation_context += f"{role}: {content}\n"

        prompt = (
            "You are a cybersecurity investigation assistant. Answer questions about the forensic analysis below.\n\n"
            "Rules:\n"
            "- If the question relates to cybersecurity, forensics, logs, incidents, or threats: give a detailed expert answer.\n"
            "- If the question is unrelated to cybersecurity: reply ONLY with 'Sorry, I don't have information about that.'\n"
            "- Be concise and professional. No meta-commentary.\n\n"
            f"{context}"
            f"{conversation_context}\n"
            f"Question: {question}\n\n"
            "Answer:"
        )

        output = self._call_api(prompt, max_tokens=800, temperature=0.3)

        if output and len(output) > 20:
            return output
        return None

    # -------------------------------------------------------------------------
    # Internal: Parse LLM JSON output
    # -------------------------------------------------------------------------

    def _parse_analysis_output(self, output: str, total_lines: int, elapsed: float = 0):
        """Parse LLM JSON output into 5-tuple: (incidents, metrics, summary, iocs, recommendations)"""
        try:
            # Strip markdown code fences if present
            cleaned = re.sub(r'^```(?:json)?\s*', '', output.strip(), flags=re.MULTILINE)
            cleaned = re.sub(r'```\s*$', '', cleaned.strip(), flags=re.MULTILINE)

            # Extract JSON object
            json_match = re.search(r'\{[\s\S]*\}', cleaned)
            if not json_match:
                print("⚠️  No JSON found in LLM output")
                print(f"Output preview: {output[:300]}")
                return None

            json_str = json_match.group(0)

            # Fix common JSON issues
            json_str = re.sub(r',\s*}', '}', json_str)
            json_str = re.sub(r',\s*]', ']', json_str)

            data = json.loads(json_str)

            incidents = data.get('incidents', [])
            iocs = data.get('iocs', [])
            recommendations = data.get('recommendations', [])
            summary_text = data.get('summary', '')

            # Normalise IOCs to list of strings
            if not isinstance(iocs, list):
                iocs = [str(iocs)] if iocs else []
            iocs = [str(i) for i in iocs]

            # Normalise recommendations to list of strings
            if not isinstance(recommendations, list):
                recommendations = [str(recommendations)] if recommendations else []
            recommendations = [str(r) for r in recommendations]

            # Validate / fix incidents
            for inc in incidents:
                if 'confidence' not in inc:
                    inc['confidence'] = 80
                if 'severity' not in inc:
                    inc['severity'] = 'medium'
                inc['severity'] = inc['severity'].lower()
                if 'type' not in inc or not inc['type']:
                    inc['type'] = 'Unknown_Threat'
                if 'detail' not in inc or not str(inc.get('detail', '')).strip():
                    inc['detail'] = (
                        f"{inc['type'].replace('_', ' ').capitalize()} detected with "
                        f"{inc['severity']} severity."
                    )

            # Build metrics
            severity_count = Counter(inc.get('severity', 'medium') for inc in incidents)
            file_metrics = {
                'events_count': total_lines,
                'critical_count': severity_count.get('critical', 0),
                'high_count': severity_count.get('high', 0),
                'medium_count': severity_count.get('medium', 0),
                'low_count': severity_count.get('low', 0),
                'total_incidents': len(incidents),
                'ioc_count': len(iocs),
            }

            # Build summary dict
            if not summary_text or summary_text.lower().startswith('none'):
                summary_text = (
                    f"Log analysis detected {len(incidents)} incidents "
                    f"and {len(iocs)} indicators of compromise. "
                    "Review detailed findings and recommendations in this report."
                )

            summary = {
                'executive': str(summary_text),
                'metadata': {
                    'file': 'analyzed',
                    'lines': total_lines,
                    'analysis_time': elapsed,
                    'incident_count': len(incidents),
                    'timestamp': datetime.now().isoformat(),
                }
            }

            print(
                f"✅ Parsed: {len(incidents)} incidents | {len(iocs)} IOCs | "
                f"{severity_count.get('critical', 0)} critical | "
                f"{severity_count.get('high', 0)} high"
            )
            return (incidents, file_metrics, summary, iocs, recommendations)

        except json.JSONDecodeError as e:
            print(f"⚠️  JSON parse error: {e}")
            print(f"Output preview: {output[:400]}")
            return None
        except Exception as e:
            print(f"❌ Parse error: {e}")
            return None


# Module-level singleton
llm_service = LLMService()
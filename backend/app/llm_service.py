"""
🔥 ENHANCED LLM SERVICE - Comprehensive Detection + Chat Context
Prompts LLM to find 30+ incidents like ChatGPT
✅ FIXED: Response truncation with increased max_tokens
✅ ADDED: Chat history context for conversation continuity
"""
from .config import USE_LLM, MODEL_PATH
import json
import re
from collections import Counter
from datetime import datetime
import time
class LLMService:
    """Enhanced LLM service for comprehensive threat detection"""

    def __init__(self):
        self.available = False
        self.model = None

        if not USE_LLM:
            print("🔧 LLM disabled in config")
            return

        try:
            from llama_cpp import Llama

            if not MODEL_PATH or not MODEL_PATH.exists():
                print(f"❌ Model not found at: {MODEL_PATH}")
                return

            print(f"\n{'='*70}")
            print(f"🤖 Loading Mistral for COMPREHENSIVE analysis...")
            print(f"📁 {MODEL_PATH.name}")
            print(f"{'='*70}\n")

            self.model = Llama(
                model_path=str(MODEL_PATH),
                n_ctx=4096,  # Larger context for better analysis
                n_threads=4,
                n_batch=256,
                n_gpu_layers=0,
                verbose=False
            )

            self.available = True
            print("✅ Model loaded - ready for deep analysis\n")

        except ImportError:
            print("❌ llama-cpp-python not installed")
        except Exception as e:
            print(f"❌ Model load failed: {e}\n")

    def analyze_logs_complete(self, filename, log_sample, total_lines):
        """
        COMPREHENSIVE log analysis - find ALL threats
        Returns: (incidents, file_metrics, summary, iocs, recommendations)
        """
        if not self.available:
            return None

        prompt_text = (
    
        "6. Output STRICT JSON ONLY:\n"
        "{\n"
        '  "incidents": [ { "type": ..., "severity": ..., "confidence": ..., "detail": ... }, ... ],\n'
        '  "iocs": [ string/object, ... ],\n'
        '  "recommendations": [ string, ... ],\n'
        '  "summary": "A 5-6 sentence executive summary describing the major findings, trends in severity, attack types, analyst priorities, and recommended next steps."\n'
        "}\n"
        "No additional text, comments, headers—ONLY JSON in the format above.\n"
        "Incidents should be actionable and security-focused; report distinct events accurately without omitting major threats or flooding the list with harmless entries.\n"
        "[/INST]"
        )



        try:
            # Build analysis prompt (keeping it simple to avoid security triggers)
            prompt_text = (
                "[INST] You are an elite cybersecurity forensic analyst.\n"
                f"Analyze this log file: {filename}\n"
                f"Sample: {min(len(log_sample.splitlines()),1800)}/{total_lines} lines\n\n"
                f"LOG SAMPLE:\n{log_sample[:1800]}\n\n"
                "TASK:\n"
                "1. Identify and enumerate ALL possible security threats, anomalies, and suspicious patterns found in the provided log data. Do not skip any plausible findings; err on the side of returning more incidents rather than fewer.\n"
                "2. Output STRICT JSON with these keys ONLY: incidents, iocs, recommendations, summary.\n"
                "3. For each incident, include: {type, severity, confidence, detail}. The 'type' must be specific (not generic). The 'detail' MUST be a unique, clear English sentence for this incident (not a generic phrase or repeated text).\n"
                "4. The 'incidents' list must be comprehensive and deterministic—the same log should produce the same incidents every time. Do not randomly drop or reorder.\n"
                "5. The 'summary' key MUST be present and filled with a 5-6 sentence business-level summary in English describing findings, severity, and recommendations for mitigation—do NOT skip or leave blank.\n"
                "6. 'iocs': List of any indicators of compromise found.\n"
                "7. 'recommendations': List of all recommended actions or mitigations.\n"
                "8. OUTPUT ONLY JSON—NO TEXT OUTSIDE THE JSON, NO HEADERS, NO COMMENTS.\n"
                "The analysis must be repeatable and not change for the same input.\n"
                "[/INST]"
            )

            print(f"🤖 LLM performing deep analysis...")

            # Generate with more tokens for comprehensive results
            llm_start = time.time()
            response = self.model(
                prompt_text,
                max_tokens=2000,  # Much more tokens for comprehensive results
                temperature=0.0,
                top_p=1.0,
                repeat_penalty=1.1,
                stop=["[INST]", "</s>", "[/INST]"]
            )

            output = response['choices'][0]['text'].strip()
            print(f"📊 Generated {len(output)} chars")

            # Parse
            parse_start = time.time()
            parsed = self._parse_comprehensive_output(output, total_lines)
            parse_elapsed = time.time() - parse_start
            llm_elapsed = time.time() - llm_start

            incidents, file_metrics, summary, iocs, recommendations = parsed
            if isinstance(summary, dict):
                if "metadata" not in summary:
                    summary["metadata"] = {}
                # Prefer total analysis (LLM + parse), or just parse
                summary["metadata"]["analysis_time"] = llm_elapsed
            return incidents, file_metrics, summary, iocs, recommendations

        except Exception as e:
            print(f"❌ LLM error: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _parse_comprehensive_output(self, output, total_lines):
        """Parse LLM output into 5-tuple"""
        try:
            # Extract JSON (handle various formats)
            json_match = re.search(r'\{[\s\S]*\}', output)
            if not json_match:
                print("⚠️ No JSON in output")
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

            if not isinstance(iocs, list):
                try:
                    if isinstance(iocs, dict):
                        iocs = list(iocs.values())
                    else:
                        iocs = [iocs]  # Make a single-item list
                except Exception:
                    iocs = []

            # Validate and fix incidents
            for inc in incidents:
                if 'confidence' not in inc:
                    inc['confidence'] = 80
                if 'severity' not in inc:
                    inc['severity'] = 'medium'
                if 'type' not in inc:
                    inc['type'] = 'Unknown_Threat'
                if 'detail' not in inc or not inc['detail'].strip():
                    # Improved: generate fallback description from type/severity/other keys
                    inc['detail'] = (
                        f"{inc['type'].replace('_', ' ').capitalize()} detected with "
                        f"{inc['severity']} severity and {inc['confidence']}% confidence."
                    )

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


            summary_string = data.get('summary', '').strip()
            if not summary_string or summary_string.lower().startswith('none'):
                summary_string = (
                    f"Log analysis detected {len(incidents)} incidents "
                    f"and {len(iocs)} indicators of compromise. "
                    "Review detailed findings and recommendations in this report."
                )

            summary_metadata = {
                'file': 'analyzed',
                'lines': total_lines,
                'analysis_time': 0,
                'incident_count': len(incidents),
                'timestamp': datetime.now().isoformat()
            }

            # ------ Return both as a single summary object ------
            summary = {
                "executive": summary_string,
                "metadata": summary_metadata
            }


            print(f"✅ Parsed: {len(incidents)} incidents, {len(iocs)} IOCs, {len(recommendations)} recommendations")
            print(f"  🔴 Critical: {severity_count.get('critical', 0)}")
            print(f"  🟠 High: {severity_count.get('high', 0)}")
            print(f"  🟡 Medium: {severity_count.get('medium', 0)}")

            return (incidents, file_metrics, summary, iocs, recommendations)

        except json.JSONDecodeError as e:
            print(f"⚠️ JSON parse error: {e}")
            print(f"Output preview: {output[:300]}...")
            return None
        except Exception as e:
            print(f"❌ Parse error: {e}")
            return None



    def answer_question(self, question, analysis_data, chat_history=None):
        # ↑ New parameter
        """Enhanced Q&A with chat context for continuity

        Args:
            question: User's question
            analysis_data: Analysis record containing incidents, metrics, etc.
            chat_history: List of previous messages [{"role": "user|assistant", "content": "..."}]

        Returns:
            Answer string or None
        """
        if not self.available:
            return None

        try:
            # Build analysis context
            metrics = analysis_data.get('file_metrics', {})
            incidents = analysis_data.get('incidents', [])[:15]

            context = f"""FORENSIC ANALYSIS SUMMARY:
File: {analysis_data.get('filename', 'Unknown')}
Total Events: {metrics.get('events_count', 0)}
Incidents: {metrics.get('total_incidents', 0)} ({metrics.get('critical_count', 0)} critical, {metrics.get('high_count', 0)} high)

TOP INCIDENTS:
"""

            for i, inc in enumerate(incidents, 1):
                context += f"{i}. [{inc.get('severity', '?').upper()}] {inc.get('type', 'Unknown')} (Confidence: {inc.get('confidence', 'N/A')}%)\n"
                context += f"   {inc.get('detail', 'No details')[:80]}...\n"

            # ✅ ENHANCEMENT: Add chat history for context continuity
            conversation_context = ""
            if chat_history and len(chat_history) > 0:
                conversation_context = "\n\nPREVIOUS CONVERSATION:\n"
                recent_messages = chat_history[-6:]  # Last 6 messages
                for msg in recent_messages:
                    role = msg.get('role', 'unknown').upper()
                    content = msg.get('content', '')[:150]
                    conversation_context += f"{role}: {content}\n"

            # Build QA prompt
            prompt_text = (
                """[INST]
                You are a cybersecurity investigation assistant.

                Rules:
                1️⃣ If the question is related to cybersecurity, digital forensics, logs, incidents, threats, vulnerabilities, or the provided analysis → give a detailed expert answer using the context.
                2️⃣ If the question is NOT related to cybersecurity or forensics → reply ONLY with:
                    "Sorry, I don't have information about that."
                3️⃣ Do NOT explain why.
                4️⃣ Do NOT mention logs, security scope, or your capabilities.
                5️⃣ Do NOT redirect the user to other topics.
                6️⃣ No long refusals. No meta commentary.
                7️⃣ Never produce off-topic content.

                Follow these rules for every response.

                Now analyze the context and question that follow and respond accordingly.
                \n\n"""
            )
            prompt_text += context
            prompt_text += conversation_context
            prompt_text += f"\n\nQuestion: {question}\n\n"
            prompt_text += "Answer: [/INST]"

            response = self.model(
                prompt_text,
                max_tokens=1000,  # ✅ Changed from 400 to 1000
                temperature=0.6,
                top_p=0.95
            )

            answer = response['choices'][0]['text'].strip()

            if len(answer) > 50:
                return answer

        except Exception as e:
            print(f"❌ Chat error: {e}")
            return None

# Initialize
llm_service = LLMService()
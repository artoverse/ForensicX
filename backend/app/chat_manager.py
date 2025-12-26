"""Chat management and Q&A module - ENHANCED with chat history context"""

from .llm_service import llm_service
from .utils import load_chat_history, save_chat_history, get_analysis_by_id

def get_rule_based_answer(question):
    """Rule-based fallback answers when LLM is unavailable"""
    q_lower = (question or '').lower()

    if 'timeline' in q_lower:
        return 'Timeline analysis shows multiple suspicious events clustered within a short timeframe indicating coordinated attack activity.'

    if 'ioc' in q_lower or 'indicator' in q_lower:
        return 'Top IOCs identified: suspicious destination ports (3389, 4444), orphan process starts, suspicious domains (.xyz, .tk), and DNS flood patterns.'

    if 'affected' in q_lower or 'system' in q_lower or 'host' in q_lower:
        return 'Affected systems show repeated authentication failures, abnormal DNS queries, and connections to suspicious external IPs.'

    if 'next' in q_lower or 'step' in q_lower or 'action' in q_lower or 'do' in q_lower:
        return 'Recommended actions: 1) Isolate affected hosts immediately, 2) Reset all credentials, 3) Review firewall logs, 4) Block C2 domains, 5) Update security signatures.'

    if 'severity' in q_lower or 'risk' in q_lower:
        return 'This incident is assessed as HIGH RISK. Multiple critical indicators suggest active compromise requiring immediate incident response activation.'

    if 'motive' in q_lower or 'goal' in q_lower or 'objective' in q_lower:
        return 'Based on observed patterns, the attacker appears to be targeting sensitive data exfiltration and maintaining persistence through credential compromise.'

    return 'I can help with: timeline analysis, IOC summary, affected systems, recommended actions, severity assessment, or attack objectives. Ask me anything about the forensic findings!'

def answer_question(log_id, question, analyses=None):
    """
    Answer user question about specific analysis.
    Uses LLM if available with chat history context, falls back to rule-based answers.
    """
    # Get the analysis
    analysis = get_analysis_by_id(log_id)
    if not analysis:
        return "Analysis not found for this case."

    # ✅ NEW: Load chat history for this specific log
    chat_history = load_chat_history(log_id)

    # ✅ NEW: Pass chat history to LLM
    if llm_service.available:
        answer = llm_service.answer_question(
            question, 
            analysis, 
            chat_history=chat_history  # ← Chat history passed here
        )
        if answer:
            return answer

    return get_rule_based_answer(question)

def get_chat_history(log_id):
    """Get chat history for analysis"""
    return load_chat_history(log_id)

def add_to_chat_history(log_id, role, content):
    """Add message to chat history"""
    messages = load_chat_history(log_id)
    messages.append({'role': role, 'content': content})
    save_chat_history(log_id, messages)
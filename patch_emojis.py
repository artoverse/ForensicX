path = '/Volumes/dr3/proj/ps2/final/ForensicX/frontend/public/index.html'
with open(path, 'r') as f:
    content = f.read()

content = content.replace('▶ Run Analysis', '<i data-lucide="play" width="16" height="16"></i> Run Analysis')
content = content.replace('🗑 Clear', '<i data-lucide="trash-2" width="16" height="16"></i> Clear')
content = content.replace('⬇️ Download PDF', '<i data-lucide="download" width="16" height="16"></i> Download PDF')
content = content.replace('⬇️ Download JSON', '<i data-lucide="download" width="16" height="16"></i> Download JSON')
content = content.replace('💬 Ask AI', '<i data-lucide="message-circle" width="16" height="16"></i> Ask AI')

content = content.replace('⏱ Timeline?', '<i data-lucide="clock" width="14" height="14"></i> Timeline?')
content = content.replace('🎯 Top IOCs?', '<i data-lucide="target" width="14" height="14"></i> Top IOCs?')
content = content.replace('🖥 Systems?', '<i data-lucide="monitor" width="14" height="14"></i> Systems?')
content = content.replace('🔴 Severity?', '<i data-lucide="alert-circle" width="14" height="14"></i> Severity?')

content = content.replace('<div class="message-avatar bot">🤖</div>', '<div class="message-avatar bot"><i data-lucide="bot" color="white"></i></div>')
content = content.replace('<div class="message-avatar bot">🤖</div>', '<div class="message-avatar bot"><i data-lucide="bot" color="white"></i></div>')

with open(path, 'w') as f:
    f.write(content)
print("More emojis patched!")

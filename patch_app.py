import re

path = '/Volumes/dr3/proj/ps2/final/ForensicX/frontend/public/app.js'
with open(path, 'r') as f:
    content = f.read()

# Add lucide.createIcons() to DOMContentLoaded
content = content.replace('checkModelStatus();\n    document.getElementById', 'checkModelStatus();\n    lucide.createIcons();\n    document.getElementById')

# Fix checkModelStatus output to use Lucide icons
content = content.replace('<span style="color: var(--success); font-weight: 600;">🟢 Connected to Mistral-7B</span>', 
                          '<i data-lucide="check-circle" color="var(--success)" width="18" height="18"></i> <span style="color: var(--success); font-weight: 600;">Connected</span>')
content = content.replace('<span style="color: var(--warning); font-weight: 600;">🟡 Heuristics Only (No LLM)</span>', 
                          '<i data-lucide="alert-triangle" color="var(--warning)" width="18" height="18"></i> <span style="color: var(--warning); font-weight: 600;">Heuristics Only</span>')
content = content.replace('<span style="color: var(--danger); font-weight: 600;">🔴 Disconnected</span>', 
                          '<i data-lucide="x-circle" color="var(--danger)" width="18" height="18"></i> <span style="color: var(--danger); font-weight: 600;">Disconnected</span>')

# Call lucide.createIcons() after updating model status to render the newly injected icons
content = content.replace('modelNameEl.innerHTML = ', 'modelNameEl.innerHTML = ')
# We need to inject lucide.createIcons() inside the checkModelStatus function where we update innerHTML.
content = re.sub(r'(modelNameEl\.innerHTML = .*?;)', r'\1\n            lucide.createIcons();', content)

with open(path, 'w') as f:
    f.write(content)
print("app.js patched!")

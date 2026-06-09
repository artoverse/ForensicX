import re

path = '/Volumes/dr3/proj/ps2/final/ForensicX/frontend/public/index.html'
with open(path, 'r') as f:
    content = f.read()

# Add Lucide script
content = content.replace('</head>', '    <script src="https://unpkg.com/lucide@latest"></script>\n</head>')

# Replace nav icons
content = content.replace('<span class="nav-icon">📊</span>', '<i data-lucide="layout-dashboard" class="nav-icon"></i>')
content = content.replace('<span class="nav-icon">📋</span>', '<i data-lucide="file-text" class="nav-icon"></i>')
content = content.replace('<span class="nav-icon">📈</span>', '<i data-lucide="bar-chart-2" class="nav-icon"></i>')
content = content.replace('<span class="nav-icon">💡</span>', '<i data-lucide="lightbulb" class="nav-icon"></i>')
content = content.replace('<span class="nav-icon">💬</span>', '<i data-lucide="message-square" class="nav-icon"></i>')

# Replace metric icons
content = content.replace('<div class="metric-icon">📁</div>', '<div class="metric-icon"><i data-lucide="folder" width="36" height="36"></i></div>')
content = content.replace('<div class="metric-icon">📊</div>', '<div class="metric-icon"><i data-lucide="activity" width="36" height="36"></i></div>')
content = content.replace('<div class="metric-icon">🔴</div>', '<div class="metric-icon"><i data-lucide="alert-triangle" width="36" height="36" color="var(--danger)"></i></div>')

# Replace upload icon
content = content.replace('<div class="upload-icon">📤</div>', '<div class="upload-icon"><i data-lucide="upload-cloud" width="48" height="48"></i></div>')

# Fix Model Name label style
content = content.replace('<div class="model-name">Mistral-7B via HuggingFace</div>', '<div class="model-name" style="display:flex; align-items:center; gap:6px;">Checking status...</div>')

# Replace other random emojis if desired
content = content.replace('<h2>📂', '<h2 style="display:flex; align-items:center; gap:8px;"><i data-lucide="folder-open"></i>')
content = content.replace('<h2>📝', '<h2 style="display:flex; align-items:center; gap:8px;"><i data-lucide="file-search"></i>')
content = content.replace('<h2>🎯', '<h2 style="display:flex; align-items:center; gap:8px;"><i data-lucide="target"></i>')
content = content.replace('<h2>📄', '<h2 style="display:flex; align-items:center; gap:8px;"><i data-lucide="file-text"></i>')
content = content.replace('<h2>💡', '<h2 style="display:flex; align-items:center; gap:8px;"><i data-lucide="lightbulb"></i>')
content = content.replace('<h2>💬', '<h2 style="display:flex; align-items:center; gap:8px;"><i data-lucide="message-circle"></i>')

with open(path, 'w') as f:
    f.write(content)
print("Icons patched!")

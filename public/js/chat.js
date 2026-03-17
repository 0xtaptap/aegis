// ═══════════════════════════════════════════════════════════════
// Chat — AI chat interface connecting to the LangChain agent
// Uses bottom-dock layout from index.html
// ═══════════════════════════════════════════════════════════════

const Chat = {
  isOpen: false,
  sessionId: 'session_' + Date.now(),

  // ── Initialize chat UI ─────────────────────────────────────
  init() {
    const sendBtn = document.getElementById('chatSend');
    const input = document.getElementById('chatInput');

    if (sendBtn) sendBtn.addEventListener('click', () => this.send());
    if (input) input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.send();
      }
    });
  },

  // ── Send message to agent ──────────────────────────────────
  async send() {
    const input = document.getElementById('chatInput');
    if (!input) return;
    const message = input.value.trim();
    if (!message) return;

    // Add user message to UI
    this.addMessage('user', message);
    input.value = '';
    input.focus();

    // Show typing indicator
    const typingId = this.showTyping();

    try {
      // Get current wallet context
      const walletAddress = document.getElementById('walletInput')?.value?.trim() || null;
      const chainSelect = document.getElementById('chainSelect');
      const activeChain = chainSelect?.value || 'ethereum';

      const data = await Utils.apiFetch('/api/chat', {
        method: 'POST',
        body: JSON.stringify({
          message,
          sessionId: this.sessionId,
          walletAddress,
          chain: activeChain,
        }),
      });

      // Remove typing indicator
      this.removeTyping(typingId);

      // Add agent response
      this.addMessage('assistant', data.response || data.reply || 'No response');

      // Log tools used
      if (data.toolsUsed && data.toolsUsed.length > 0) {
        const toolNames = data.toolsUsed.map(t => t.tool).join(', ');
        Monitor.addLog(`Agent used tools: ${toolNames}`);
      }

      Monitor.addLog(`Chat: "${message.slice(0, 40)}${message.length > 40 ? '…' : ''}"`);

    } catch (err) {
      this.removeTyping(typingId);
      this.addMessage('assistant', `⚠️ Sorry, I hit an error: ${err.message}\n\nTip: Make sure your API key is set in the .env file.`);
    }
  },

  // ── Add message to chat ────────────────────────────────────
  addMessage(role, content) {
    const container = document.getElementById('chatMessages');
    if (!container) return;
    const avatar = role === 'assistant' ? '🛡️' : '👤';

    // Process markdown-light formatting
    const formatted = content
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code style="background:rgba(100,140,255,0.1);padding:1px 4px;border-radius:3px;font-family:var(--font-mono);font-size:0.8rem;">$1</code>')
      .replace(/\n/g, '<br>');

    const msg = Utils.el('div', { className: `chat-msg ${role}` }, [
      Utils.el('div', { className: 'msg-avatar', textContent: avatar }),
      Utils.el('div', { className: 'msg-content', innerHTML: `<p>${formatted}</p>` }),
    ]);

    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
  },

  // ── Typing indicator ──────────────────────────────────────
  showTyping() {
    const container = document.getElementById('chatMessages');
    if (!container) return null;
    const id = 'typing_' + Date.now();

    const msg = Utils.el('div', { className: 'chat-msg assistant', id }, [
      Utils.el('div', { className: 'msg-avatar', textContent: '🛡️' }),
      Utils.el('div', { className: 'msg-content msg-typing', innerHTML: `
        <span class="typing-dot"></span>
        <span class="typing-dot"></span>
        <span class="typing-dot"></span>
      ` }),
    ]);

    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
    return id;
  },

  removeTyping(id) {
    if (!id) return;
    const el = document.getElementById(id);
    if (el) el.remove();
  },
};

window.Chat = Chat;

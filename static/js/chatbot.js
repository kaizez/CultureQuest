// AI Chatbot Functionality
class CultureQuestChatbot {
    constructor() {
        this.isOpen = false;
        this.isTyping = false;
        this.init();
    }

    init() {
        this.createChatbotHTML();
        this.attachEventListeners();
        this.addWelcomeMessage();
    }

    createChatbotHTML() {
        // Create chatbot bubble
        const bubble = document.createElement('div');
        bubble.className = 'chatbot-bubble';
        bubble.innerHTML = '<i class="fas fa-robot"></i>';
        bubble.id = 'chatbot-bubble';
        
        // Create chatbot container
        const container = document.createElement('div');
        container.className = 'chatbot-container';
        container.id = 'chatbot-container';
        container.innerHTML = `
            <div class="chatbot-header">
                <h3>🌿 CultureQuest FAQ</h3>
                <button class="chatbot-close" id="chatbot-close">×</button>
            </div>
            <div class="chatbot-messages" id="chatbot-messages"></div>
            <div class="chatbot-input-container">
                <input type="text" class="chatbot-input" id="chatbot-input" placeholder="Ask me anything about CultureQuest...">
                <button class="chatbot-send" id="chatbot-send">
                    <i class="fas fa-paper-plane"></i>
                </button>
            </div>
        `;
        
        document.body.appendChild(bubble);
        document.body.appendChild(container);
    }

    attachEventListeners() {
        const bubble = document.getElementById('chatbot-bubble');
        const container = document.getElementById('chatbot-container');
        const closeBtn = document.getElementById('chatbot-close');
        const sendBtn = document.getElementById('chatbot-send');
        const input = document.getElementById('chatbot-input');

        bubble.addEventListener('click', () => this.toggleChat());
        closeBtn.addEventListener('click', () => this.closeChat());
        sendBtn.addEventListener('click', () => this.sendMessage());
        
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Close chat when clicking outside
        document.addEventListener('click', (e) => {
            if (this.isOpen && !container.contains(e.target) && !bubble.contains(e.target)) {
                this.closeChat();
            }
        });
    }

    toggleChat() {
        if (this.isOpen) {
            this.closeChat();
        } else {
            this.openChat();
        }
    }

    openChat() {
        const container = document.getElementById('chatbot-container');
        const bubble = document.getElementById('chatbot-bubble');
        
        container.style.display = 'flex';
        bubble.style.display = 'none';
        this.isOpen = true;
        
        // Focus input
        setTimeout(() => {
            document.getElementById('chatbot-input').focus();
        }, 100);
    }

    closeChat() {
        const container = document.getElementById('chatbot-container');
        const bubble = document.getElementById('chatbot-bubble');
        
        container.style.display = 'none';
        bubble.style.display = 'flex';
        this.isOpen = false;
    }

    addWelcomeMessage() {
        setTimeout(() => {
            this.addBotMessage("👋 Hi! I'm your CultureQuest FAQ assistant. Ask me anything about challenges, rewards, chat features, or how to use the platform!");
        }, 500);
    }

    addBotMessage(message) {
        const messagesContainer = document.getElementById('chatbot-messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'chatbot-message bot';
        messageDiv.innerHTML = `
            <div class="avatar">🤖</div>
            <div class="content">${this.formatMessage(message)}</div>
        `;
        messagesContainer.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addStreamingBotMessage() {
        const messagesContainer = document.getElementById('chatbot-messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'chatbot-message bot';
        messageDiv.innerHTML = `
            <div class="avatar">🤖</div>
            <div class="content"></div>
        `;
        messagesContainer.appendChild(messageDiv);
        this.scrollToBottom();
        return messageDiv;
    }

    addUserMessage(message) {
        const messagesContainer = document.getElementById('chatbot-messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'chatbot-message user';
        messageDiv.innerHTML = `
            <div class="avatar">👤</div>
            <div class="content">${this.escapeHtml(message)}</div>
        `;
        messagesContainer.appendChild(messageDiv);
        this.scrollToBottom();
    }

    showTyping() {
        if (this.isTyping) return;
        
        this.isTyping = true;
        const messagesContainer = document.getElementById('chatbot-messages');
        const typingDiv = document.createElement('div');
        typingDiv.className = 'chatbot-typing';
        typingDiv.id = 'typing-indicator';
        typingDiv.innerHTML = `
            <div class="avatar">🤖</div>
            <div class="typing-dots">
                <span></span>
                <span></span>
                <span></span>
            </div>
        `;
        messagesContainer.appendChild(typingDiv);
        this.scrollToBottom();
    }

    hideTyping() {
        const typingIndicator = document.getElementById('typing-indicator');
        if (typingIndicator) {
            typingIndicator.remove();
        }
        this.isTyping = false;
    }

    async sendMessage() {
        const input = document.getElementById('chatbot-input');
        const sendBtn = document.getElementById('chatbot-send');
        const message = input.value.trim();
        
        if (!message) return;
        
        // Disable input
        input.disabled = true;
        sendBtn.disabled = true;
        
        // Add user message
        this.addUserMessage(message);
        input.value = '';
        
        // Hide typing indicator and add streaming bot message container
        this.hideTyping();
        const botMessageDiv = this.addStreamingBotMessage();
        const contentDiv = botMessageDiv.querySelector('.content');
        
        try {
            const response = await fetch('/api/chatbot', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: message })
            });
            
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            
            // Handle streaming response
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let botResponse = '';
            
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                const chunk = decoder.decode(value);
                const lines = chunk.split('\n');
                
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        try {
                            const data = JSON.parse(line.slice(6));
                            if (data.response) {
                                botResponse += data.response;
                                contentDiv.innerHTML = this.formatMessage(botResponse);
                                this.scrollToBottom();
                            }
                            if (data.done) {
                                break;
                            }
                        } catch (e) {
                            // Ignore JSON parse errors
                        }
                    }
                }
            }
            
        } catch (error) {
            console.error('Chatbot error:', error);
            contentDiv.innerHTML = "I'm sorry, I'm having trouble connecting right now. Please try again in a moment.";
        } finally {
            // Re-enable input
            input.disabled = false;
            sendBtn.disabled = false;
            input.focus();
        }
    }

    scrollToBottom() {
        const messagesContainer = document.getElementById('chatbot-messages');
        setTimeout(() => {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }, 50);
    }

    formatMessage(message) {
        // Convert markdown-style formatting to HTML
        let formatted = this.escapeHtml(message);
        
        // Bold text **text**
        formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        
        // Convert line breaks
        formatted = formatted.replace(/\n/g, '<br>');
        
        return formatted;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Check if we should show the chatbot on this page
    shouldShowChatbot() {
        const path = window.location.pathname;
        
        // Don't show on admin pages
        if (path.includes('/admin/') || path.includes('/moderate/')) {
            return false;
        }
        
        // Don't show on chat pages/sessions
        if (path.includes('/chat') || path.includes('/session/')) {
            return false;
        }
        
        // Show on all other pages
        return true;
    }
}

// Initialize chatbot when page loads
document.addEventListener('DOMContentLoaded', function() {
    const chatbot = new CultureQuestChatbot();
    
    // Hide chatbot on admin pages
    if (!chatbot.shouldShowChatbot()) {
        const bubble = document.getElementById('chatbot-bubble');
        const container = document.getElementById('chatbot-container');
        if (bubble) bubble.style.display = 'none';
        if (container) container.style.display = 'none';
    }
});
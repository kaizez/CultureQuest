// Admin 2FA Popup System
class Admin2FA {
    constructor() {
        this.maxAttempts = 5;
        this.currentAttempts = 0;
        this.isLocked = false;
        this.popup = null;
        this.init();
    }

    init() {
        this.createPopupHTML();
        this.bindEvents();
    }

    createPopupHTML() {
        const popupHTML = `
            <div id="admin-2fa-overlay" class="admin-2fa-overlay" style="display: none;">
                <div class="admin-2fa-popup">
                    <div class="admin-2fa-header">
                        <h2>🔐 Admin Two-Factor Authentication</h2>
                        <p>Enter your 2FA security code to access admin dashboard</p>
                    </div>
                    
                    <div class="admin-2fa-body">
                        <div class="admin-2fa-input-container">
                            <input 
                                type="text" 
                                id="admin-2fa-code" 
                                placeholder="Enter 2FA code" 
                                maxlength="20"
                                autocomplete="off"
                                spellcheck="false"
                            />
                        </div>
                        
                        <div class="admin-2fa-attempts">
                            <span id="attempts-remaining">Remaining attempts: <strong style="color: #dc3545;">5</strong></span>
                        </div>
                        
                        <div class="admin-2fa-buttons">
                            <button id="admin-2fa-submit" class="admin-2fa-btn admin-2fa-btn-primary">
                                Verify Code
                            </button>
                            <button id="admin-2fa-cancel" class="admin-2fa-btn admin-2fa-btn-secondary">
                                Cancel
                            </button>
                        </div>
                        
                        <div id="admin-2fa-message" class="admin-2fa-message" style="display: none;"></div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', popupHTML);
        this.popup = document.getElementById('admin-2fa-overlay');
    }

    bindEvents() {
        const submitBtn = document.getElementById('admin-2fa-submit');
        const cancelBtn = document.getElementById('admin-2fa-cancel');
        const codeInput = document.getElementById('admin-2fa-code');

        submitBtn.addEventListener('click', () => this.verifyCode());
        cancelBtn.addEventListener('click', () => this.cancel());
        
        // Allow Enter key to submit
        codeInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !this.isLocked) {
                this.verifyCode();
            }
        });

        // Prevent closing popup by clicking overlay
        this.popup.addEventListener('click', (e) => {
            if (e.target === this.popup) {
                // Don't close - force user to use Cancel or verify
                this.showMessage('Please enter the 2FA code or click Cancel to logout.', 'warning');
            }
        });
    }

    show() {
        this.popup.style.display = 'flex';
        document.getElementById('admin-2fa-code').focus();
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
    }

    hide() {
        this.popup.style.display = 'none';
        document.body.style.overflow = 'auto';
    }

    async verifyCode() {
        if (this.isLocked) {
            this.showMessage('Input is locked due to too many failed attempts.', 'error');
            return;
        }

        const inputCode = document.getElementById('admin-2fa-code').value.trim();
        
        if (!inputCode) {
            this.showMessage('Please enter a 2FA code.', 'warning');
            return;
        }

        try {
            const response = await fetch('/admin/2fa/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ code: inputCode })
            });

            const result = await response.json();

            if (result.success) {
                this.showMessage('Code verified successfully! Redirecting...', 'success');
                setTimeout(() => {
                    this.hide();
                    window.location.href = '/admin/dashboard';
                }, 1500);
            } else {
                this.currentAttempts++;
                const remainingAttempts = this.maxAttempts - this.currentAttempts;
                
                this.updateAttemptsDisplay(remainingAttempts);
                
                if (remainingAttempts <= 0) {
                    this.lockInput();
                    this.sendSecurityAlert();
                } else {
                    this.showMessage(
                        `Invalid code. ${remainingAttempts} attempt${remainingAttempts !== 1 ? 's' : ''} remaining.`, 
                        'error'
                    );
                }
                
                // Clear input
                document.getElementById('admin-2fa-code').value = '';
            }
        } catch (error) {
            console.error('2FA verification error:', error);
            this.showMessage('Network error. Please try again.', 'error');
        }
    }

    updateAttemptsDisplay(remaining) {
        const attemptsElement = document.getElementById('attempts-remaining');
        attemptsElement.innerHTML = `Remaining attempts: <strong style="color: #dc3545;">${remaining}</strong>`;
    }

    lockInput() {
        this.isLocked = true;
        const codeInput = document.getElementById('admin-2fa-code');
        const submitBtn = document.getElementById('admin-2fa-submit');
        
        codeInput.disabled = true;
        codeInput.style.backgroundColor = '#f8f9fa';
        codeInput.style.cursor = 'not-allowed';
        
        submitBtn.disabled = true;
        submitBtn.textContent = 'LOCKED';
        submitBtn.style.backgroundColor = '#dc3545';
        
        this.showMessage('Access locked due to multiple failed attempts. Security notification sent.', 'error');
    }

    async sendSecurityAlert() {
        try {
            const response = await fetch('/admin/security-alert', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    event: '2FA_BREACH_ATTEMPT',
                    timestamp: new Date().toISOString(),
                    attempts: this.currentAttempts
                })
            });
            
            if (response.ok) {
                console.log('Security alert sent successfully');
            }
        } catch (error) {
            console.error('Failed to send security alert:', error);
        }
    }

    showMessage(text, type = 'info') {
        const messageElement = document.getElementById('admin-2fa-message');
        messageElement.textContent = text;
        messageElement.className = `admin-2fa-message admin-2fa-message-${type}`;
        messageElement.style.display = 'block';
        
        // Auto-hide success and warning messages
        if (type === 'success' || type === 'warning') {
            setTimeout(() => {
                messageElement.style.display = 'none';
            }, 3000);
        }
    }

    cancel() {
        // Log out the user and redirect to login
        window.location.href = '/logout';
    }
}

// Initialize 2FA system when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize if we're on a page that needs 2FA
    if (window.needsAdmin2FA) {
        window.admin2FA = new Admin2FA();
        // Auto-show the popup
        setTimeout(() => {
            window.admin2FA.show();
        }, 500);
    }
});
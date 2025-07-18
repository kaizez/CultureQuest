$(document).ready(function () {
    const socket = io();

    // Prompt for the username and use "Anonymous" if not provided
    let userName = prompt("Enter your name:");
    if (!userName) userName = "Anonymous";

    // Load message history from server on page load
    $.getJSON('/history', function (data) {
        data.forEach(function (msg) {
            appendMessage(msg);
        });
        scrollToBottom();  // Scroll to the most recent message
    });

    // Handle form submission (either by pressing Enter or clicking the send button)
    $('#chat-form').submit(function (e) {
        e.preventDefault();  // Prevent page refresh on submit
        const message = $('#message').val().trim();  // Get the input value
        if (message) {
            // Emit message through socket.io
            socket.emit('my event', {
                user_name: userName,
                message: message
            });
            $('#message').val('').focus();  // Clear the input field after sending
        }
    });

    // Listen for new messages from the server and display them
    socket.on('my response', function (msg) {
        appendMessage(msg);  // Append the new message to the message list
        scrollToBottom();  // Scroll to the bottom of the message list
    });

    // Function to append a message to the messages list
    function appendMessage(msg) {
        const className = msg.user_name === userName ? 'user' : 'other';  // Different class for own and others' messages
        const avatarContent = className === 'user' ? '👤' : '🤖';
        const messageTime = msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : '';
        
        $('#messages').append(`
            <div class="message ${className}">
                <div class="message-avatar">
                    <span class="avatar-icon">${avatarContent}</span>
                </div>
                <div class="message-content">
                    <div class="bubble-text">${msg.message}</div>
                    <div class="message-footer">
                        <span class="timestamp">${messageTime}</span>
                        <span class="sender-name">${msg.user_name}</span>
                    </div>
                </div>
            </div>
        `);
    }

    // Function to scroll the messages div to the bottom
    function scrollToBottom() {
        const messagesDiv = $('#messages');
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);  // Scroll to the most recent message
    }
});
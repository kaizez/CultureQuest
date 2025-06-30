$(document).ready(function () {
    const socket = io();
    let userName = prompt("Enter your name:");
    if (!userName) userName = "Anonymous";

    // Load history
    $.getJSON('/history', function (data) {
        data.forEach(function (msg) {
            appendMessage(msg);
        });
        scrollToBottom();
    });

    // Handle form submit (Enter or button)
    $('#chat-form').submit(function (e) {
        e.preventDefault(); // prevent page refresh
        const message = $('#message').val().trim();
        if (message) {
            socket.emit('my event', {
                user_name: userName,
                message: message
            });
            $('#message').val('').focus();
        }
    });

    // Display new message
    socket.on('my response', function (msg) {
        appendMessage(msg);
        scrollToBottom();
    });

    function appendMessage(msg) {
        const className = msg.user_name === userName ? 'user' : 'other';
        $('#messages').append(`
            <div class="message ${className}">
                <div class="bubble-text">${msg.message}</div>
                <div class="message-footer">
                    <span class="timestamp">${msg.timestamp || ''}</span>
                    <span class="sender-name">${msg.user_name}</span>
                </div>
            </div>
        `);
    }

    function scrollToBottom() {
        const messagesDiv = $('#messages');
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);
    }
});

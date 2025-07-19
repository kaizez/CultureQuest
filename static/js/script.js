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
        const className = msg.user_name === userName ? 'user' : 'other';
        const avatarContent = className === 'user' ? '👤' : '🤖';
        const messageTime = msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : '';

        const messageDiv = $('<div>').addClass('message').addClass(className);
        const avatarDiv = $('<div>').addClass('message-avatar').append($('<span>').addClass('avatar-icon').text(avatarContent));
        const contentDiv = $('<div>').addClass('message-content');
        const bubbleDiv = $('<div>').addClass('bubble-text').text(msg.message);
        const footerDiv = $('<div>').addClass('message-footer');
        const timestampSpan = $('<span>').addClass('timestamp').text(messageTime);
        const senderSpan = $('<span>').addClass('sender-name').text(msg.user_name);

        footerDiv.append(timestampSpan).append(senderSpan);
        contentDiv.append(bubbleDiv).append(footerDiv);
        messageDiv.append(avatarDiv).append(contentDiv);

        $('#messages').append(messageDiv);
    }

    // Function to scroll the messages div to the bottom
    function scrollToBottom() {
        const messagesDiv = $('#messages');
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);  // Scroll to the most recent message
    }
});
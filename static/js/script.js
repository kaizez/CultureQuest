$(document).ready(function () {
    const socket = io();
    let selectedFile = null;

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

    // File attachment functionality
    $('#attach-file-btn').click(function() {
        $('#file-input').click();
    });

    $('#file-input').change(function() {
        const file = this.files[0];
        if (file) {
            selectedFile = file;
            showFilePreview(file);
        }
    });

    $('.remove-file-btn').click(function() {
        clearFileSelection();
    });

    // Handle form submission (either by pressing Enter or clicking the send button)
    $('#chat-form').submit(function (e) {
        e.preventDefault();  // Prevent page refresh on submit
        const message = $('#message').val().trim();  // Get the input value
        
        if (message || selectedFile) {
            if (selectedFile) {
                // Send file
                sendFileMessage(message);
            } else {
                // Send text message
                socket.emit('my event', {
                    user_name: userName,
                    message: message
                });
            }
            $('#message').val('').focus();  // Clear the input field after sending
            clearFileSelection();
        }
    });

    // Listen for new messages from the server and display them
    socket.on('my response', function (msg) {
        appendMessage(msg);  // Append the new message to the message list
        scrollToBottom();  // Scroll to the bottom of the message list
    });

    // Function to send file message
    function sendFileMessage(message) {
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('user_name', userName);
        formData.append('message', message);

        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    console.log('File uploaded successfully');
                } else {
                    alert('Error: ' + response.error);
                }
            },
            error: function(xhr, status, error) {
                console.error('Error uploading file:', error);
                const errorMsg = xhr.responseJSON ? xhr.responseJSON.error : 'An unknown error occurred.';
                alert('Error uploading file: ' + errorMsg);
            }
        });
    }

    // Function to show file preview
    function showFilePreview(file) {
        $('#file-preview .file-name').text(file.name);
        $('#file-preview').show();
    }

    // Function to clear file selection
    function clearFileSelection() {
        selectedFile = null;
        $('#file-input').val('');
        $('#file-preview').hide();
    }

    // Function to append a message to the messages list
    function appendMessage(msg) {
        const className = msg.user_name === userName ? 'user' : 'other';
        const avatarContent = className === 'user' ? '👤' : '🤖';
        const messageTime = msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : '';

        const messageDiv = $('<div>').addClass('message').addClass(className);
        const avatarDiv = $('<div>').addClass('message-avatar').append($('<span>').addClass('avatar-icon').text(avatarContent));
        const contentDiv = $('<div>').addClass('message-content');
        const bubbleDiv = $('<div>').addClass('bubble-text');
        
        // Handle file messages
        if (msg.file_url) {
            const fileName = msg.file_name || 'File';
            const fileExtension = fileName.split('.').pop().toLowerCase();
            
            if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(fileExtension)) {
                // Display image
                const imgElement = $('<img>').attr('src', msg.file_url).addClass('message-image').css({
                    'max-width': '300px',
                    'max-height': '300px',
                    'border-radius': '8px',
                    'cursor': 'pointer'
                });
                
                imgElement.click(function() {
                    window.open(msg.file_url, '_blank');
                });
                
                bubbleDiv.append(imgElement);
                
                if (msg.message) {
                    bubbleDiv.append($('<br>')).append($('<span>').text(msg.message));
                }
            } else {
                // Display file link
                const fileLink = $('<a>').attr('href', msg.file_url).attr('target', '_blank').text(fileName).addClass('file-link').css({
                    'color': '#007bff',
                    'text-decoration': 'underline'
                });
                bubbleDiv.append($('<span>').addClass('file-icon').text('📄 ')).append(fileLink);
                
                if (msg.message) {
                    bubbleDiv.append($('<br>')).append($('<span>').text(msg.message));
                }
            }
        } else {
            // Regular text message
            bubbleDiv.html(msg.message);
        }

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
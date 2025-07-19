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

    // Function to send file message with virus scanning
    function sendFileMessage(message) {
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('user_name', userName);
        formData.append('message', message);

        // Show scanning status
        const scanningId = showScanningMessage(selectedFile.name);
        
        // Disable the send button during upload
        $('.send-btn').prop('disabled', true).css('opacity', '0.6');

        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            timeout: 180000, // 3 minutes timeout for virus scanning
            success: function(response) {
                // Remove scanning message
                removeScanningMessage(scanningId);
                
                if (response.success) {
                    console.log('File uploaded successfully and passed virus scan');
                    
                    // Show success notification
                    showNotification('✅ File uploaded and virus scan passed', 'success');
                    
                    if (response.scan_details) {
                        console.log('Scan details:', response.scan_details);
                    }
                } else {
                    showNotification('❌ Error: ' + response.error, 'error');
                }
                
                // Re-enable send button
                $('.send-btn').prop('disabled', false).css('opacity', '1');
            },
            error: function(xhr, status, error) {
                console.error('Error uploading file:', error);
                
                // Remove scanning message
                removeScanningMessage(scanningId);
                
                let errorMsg = 'An unknown error occurred.';
                
                if (status === 'timeout') {
                    errorMsg = 'Upload timed out. The file may be too large or the virus scan took too long.';
                } else if (xhr.responseJSON && xhr.responseJSON.error) {
                    errorMsg = xhr.responseJSON.error;
                    
                    // Show additional scan details if available
                    if (xhr.responseJSON.scan_details) {
                        console.log('Scan details:', xhr.responseJSON.scan_details);
                    }
                }
                
                showNotification('❌ Error uploading file: ' + errorMsg, 'error');
                
                // Re-enable send button
                $('.send-btn').prop('disabled', false).css('opacity', '1');
            }
        });
    }

    // Function to show scanning message
    function showScanningMessage(fileName) {
        const scanningId = 'scanning-' + Date.now();
        const scanningMsg = {
            user_name: 'System',
            message: `🔍 Scanning "${fileName}" for viruses... Please wait.`,
            timestamp: new Date().toISOString(),
            scanning: true,
            scanning_id: scanningId
        };
        
        appendMessage(scanningMsg);
        scrollToBottom();
        
        return scanningId;
    }

    // Function to remove scanning message
    function removeScanningMessage(scanningId) {
        $(`[data-scanning-id="${scanningId}"]`).fadeOut(500, function() {
            $(this).remove();
        });
    }

    // Function to show notification
    function showNotification(message, type) {
        // Remove existing notifications
        $('.notification').remove();
        
        const notification = $('<div>').addClass('notification').addClass(type).text(message);
        
        // Style the notification
        notification.css({
            'position': 'fixed',
            'top': '20px',
            'right': '20px',
            'padding': '12px 20px',
            'border-radius': '8px',
            'color': 'white',
            'font-weight': 'bold',
            'z-index': '9999',
            'max-width': '300px',
            'word-wrap': 'break-word'
        });
        
        if (type === 'success') {
            notification.css('background-color', '#28a745');
        } else if (type === 'error') {
            notification.css('background-color', '#dc3545');
        }
        
        $('body').append(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(function() {
            notification.fadeOut(500, function() {
                notification.remove();
            });
        }, 5000);
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
        let avatarContent = className === 'user' ? '👤' : '🤖';
        
        // Special handling for system messages
        if (msg.user_name === 'System') {
            avatarContent = '⚙️';
        }
        
        const messageTime = msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : '';

        const messageDiv = $('<div>').addClass('message').addClass(className);
        
        // Add scanning ID for removal if it's a scanning message
        if (msg.scanning && msg.scanning_id) {
            messageDiv.attr('data-scanning-id', msg.scanning_id);
            messageDiv.addClass('scanning-message').css({
                'opacity': '0.8',
                'font-style': 'italic'
            });
        }
        
        const avatarDiv = $('<div>').addClass('message-avatar').append($('<span>').addClass('avatar-icon').text(avatarContent));
        const contentDiv = $('<div>').addClass('message-content');
        const bubbleDiv = $('<div>').addClass('bubble-text');
        
        // Handle file messages
        if (msg.file_url && !msg.scanning) {
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
                    bubbleDiv.append($('<br>')).append($('<div>').html(msg.message.replace(/\n/g, '<br>')));
                }
            } else {
                // Display file link
                const fileLink = $('<a>').attr('href', msg.file_url).attr('target', '_blank').text(fileName).addClass('file-link').css({
                    'color': '#007bff',
                    'text-decoration': 'underline'
                });
                bubbleDiv.append($('<span>').addClass('file-icon').text('📄 ')).append(fileLink);
                
                if (msg.message) {
                    bubbleDiv.append($('<br>')).append($('<div>').html(msg.message.replace(/\n/g, '<br>')));
                }
            }
        } else {
            // Regular text message or scanning message
            bubbleDiv.html(msg.message.replace(/\n/g, '<br>'));
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
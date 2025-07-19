$(document).ready(function () {
    const socket = io();
    let selectedFile = null;

    // Get room and user info from the DOM
    const chatContainer = $('#chat-container');
    const roomId = chatContainer.data('room-id');
    const userName = chatContainer.data('username');

    if (!roomId) {
        alert('Error: Chat room ID not found. Returning to room selection.');
        window.location.href = '/chat';
        return;
    }

    // Join the specific chat room
    socket.on('connect', function() {
        socket.emit('join', { room: roomId, username: userName });
        console.log(`Joined room ${roomId} as ${userName}`);
    });

    // Load message history for the specific room
    $.getJSON(`/history/${roomId}`, function (data) {
        data.forEach(function (msg) {
            appendMessage(msg);
        });
        scrollToBottom();
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

    // Function to detect URLs in text
    function detectURLs(text) {
        const urlRegex = /https?:\/\/(?:[a-zA-Z]|[0-9]|[$_@.&+]|[!*\\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+/g;
        return text.match(urlRegex) || [];
    }

    // Handle form submission
    $('#chat-form').submit(function (e) {
        e.preventDefault();
        const message = $('#message').val().trim();
        
        if (message || selectedFile) {
            if (selectedFile) {
                sendFileMessage(message);
            } else {
                const urls = detectURLs(message);
                if (urls.length > 0) {
                    showURLScanningIndicator(urls);
                }
                
                // Send text message with room_id
                socket.emit('my event', {
                    user_name: userName,
                    message: message,
                    room_id: roomId
                });
            }
            $('#message').val('').focus();
            clearFileSelection();
        }
    });

    // Listen for new messages from the server
    socket.on('my response', function (msg) {
        // Ensure message is for the current room
        if (msg.room_id == roomId) {
            removeURLScanningIndicator();
            appendMessage(msg);
            scrollToBottom();
        }
    });

    // Function to show URL scanning indicator
    function showURLScanningIndicator(urls) {
        const urlList = urls.map(url => `• ${url}`).join('\n');
        const scanningMsg = {
            user_name: 'System',
            message: `🔍 Scanning ${urls.length} URL(s) for threats...\n${urlList}\n\nPlease wait...`,
            timestamp: new Date().toISOString(),
            scanning: true,
            scanning_id: 'url-scanning-indicator',
            room_id: roomId
        };
        
        appendMessage(scanningMsg);
        scrollToBottom();
    }

    // Function to remove URL scanning indicator
    function removeURLScanningIndicator() {
        $('[data-scanning-id="url-scanning-indicator"]').fadeOut(300, function() {
            $(this).remove();
        });
    }

    // Function to send file message to the correct room
    function sendFileMessage(message) {
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('user_name', userName);
        formData.append('message', message);

        const scanningId = showScanningMessage(selectedFile.name);
        
        $('.send-btn').prop('disabled', true).css('opacity', '0.6');

        $.ajax({
            url: `/upload/${roomId}`, // Use room-specific upload URL
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            timeout: 180000,
            success: function(response) {
                removeScanningMessage(scanningId);
                if (response.success) {
                    showNotification('✅ File uploaded and virus scan passed', 'success');
                } else {
                    showNotification('❌ Error: ' + response.error, 'error');
                }
                $('.send-btn').prop('disabled', false).css('opacity', '1');
            },
            error: function(xhr, status, error) {
                removeScanningMessage(scanningId);
                let errorMsg = 'An unknown error occurred.';
                if (status === 'timeout') {
                    errorMsg = 'Upload timed out. The file may be too large or the virus scan took too long.';
                } else if (xhr.responseJSON && xhr.responseJSON.error) {
                    errorMsg = xhr.responseJSON.error;
                }
                showNotification('❌ Error uploading file: ' + errorMsg, 'error');
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
            scanning_id: scanningId,
            room_id: roomId
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
        } else if (type === 'warning') {
            notification.css('background-color', '#ffc107');
            notification.css('color', '#212529');
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
                'font-style': 'italic',
                'background-color': '#f8f9fa',
                'border-left': '4px solid #17a2b8'
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
                    bubbleDiv.append($('<br>')).append($('<div>').html(formatMessage(msg.message)));
                }
            } else {
                // Display file link
                const fileLink = $('<a>').attr('href', msg.file_url).attr('target', '_blank').text(fileName).addClass('file-link').css({
                    'color': '#ffffff',
                    'text-decoration': 'underline'
                });
                bubbleDiv.append($('<span>').addClass('file-icon').text('📄 ')).append(fileLink);
                
                if (msg.message) {
                    bubbleDiv.append($('<br>')).append($('<div>').html(formatMessage(msg.message)));
                }
            }
        } else {
            // Regular text message or scanning message
            bubbleDiv.html(formatMessage(msg.message));
        }

        const footerDiv = $('<div>').addClass('message-footer');
        const timestampSpan = $('<span>').addClass('timestamp').text(messageTime);
        const senderSpan = $('<span>').addClass('sender-name').text(msg.user_name);

        footerDiv.append(timestampSpan).append(senderSpan);
        contentDiv.append(bubbleDiv).append(footerDiv);
        messageDiv.append(avatarDiv).append(contentDiv);

        $('#messages').append(messageDiv);
    }

    // Function to format message text with enhanced URL scan result styling
    function formatMessage(message) {
        let formattedMessage = message.replace(/\n/g, '<br>');
        
        // Enhanced styling for URL scan results
        formattedMessage = formattedMessage.replace(
            /🔍 URL Scan Results:/g, 
            '<div style="margin-top: 10px; font-weight: bold; color: #17a2b8;">🔍 URL Scan Results:</div>'
        );
        
        // Style safe URLs
        formattedMessage = formattedMessage.replace(
            /✅ (https?:\/\/[^\s]+): ([^<\n]+)/g,
            '<div style="margin: 5px 0; padding: 8px; background-color: #d4edda; border-radius: 4px; border-left: 4px solid #28a745;">' +
            '<div style="font-weight: bold; color: #155724;">✅ Safe URL</div>' +
            '<div style="font-family: monospace; font-size: 0.9em; color: #155724; word-break: break-all;">$1</div>' +
            '<div style="font-size: 0.9em; color: #155724;">$2</div>' +
            '</div>'
        );
        
        // Style potentially dangerous URLs
        formattedMessage = formattedMessage.replace(
            /⚠️ (https?:\/\/[^\s]+): ([^<\n]+)/g,
            '<div style="margin: 5px 0; padding: 8px; background-color: #f8d7da; border-radius: 4px; border-left: 4px solid #dc3545;">' +
            '<div style="font-weight: bold; color: #721c24;">⚠️ Potential Threat Detected</div>' +
            '<div style="font-family: monospace; font-size: 0.9em; color: #721c24; word-break: break-all;">$1</div>' +
            '<div style="font-size: 0.9em; color: #721c24;">$2</div>' +
            '</div>'
        );
        
        // Style virus scan results for files
        formattedMessage = formattedMessage.replace(
            /✅ Virus scan passed:/g,
            '<div style="margin-top: 10px; color: #28a745; font-weight: bold;">✅ Virus scan passed:</div>'
        );
        
        formattedMessage = formattedMessage.replace(
            /⚠️ Uploaded without virus scan/g,
            '<div style="margin-top: 10px; color: #ffc107; font-weight: bold;">⚠️ Uploaded without virus scan</div>'
        );
        
        return formattedMessage;
    }

    // Function to scroll the messages div to the bottom
    function scrollToBottom() {
        const messagesDiv = $('#messages');
        messagesDiv.scrollTop(messagesDiv[0].scrollHeight);  // Scroll to the most recent message
    }

    // Input field enhancements for URL detection
    $('#message').on('input', function() {
        const message = $(this).val();
        const urls = detectURLs(message);
        
        // Optional: Visual indication when URLs are detected
        if (urls.length > 0) {
            $(this).css('border-left', '3px solid #17a2b8');
            
            // Optional: Show tooltip or indicator that URLs will be scanned
            if (!$('#url-detected-indicator').length) {
                const indicator = $('<div id="url-detected-indicator" style="position: absolute; right: 50px; top: 50%; transform: translateY(-50%); color: #17a2b8; font-size: 12px; pointer-events: none;">🔍 URLs detected</div>');
                $(this).parent().css('position', 'relative').append(indicator);
            }
        } else {
            $(this).css('border-left', '');
            $('#url-detected-indicator').remove();
        }
    });

    // Remove URL indicator when input loses focus
    $('#message').on('blur', function() {
        setTimeout(function() {
            $('#url-detected-indicator').remove();
        }, 2000);
    });
});
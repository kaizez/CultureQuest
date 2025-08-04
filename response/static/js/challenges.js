    document.addEventListener('DOMContentLoaded', function() {
        const step1 = document.getElementById('step-1');
        const step2 = document.getElementById('step-2');
        const step3 = document.getElementById('step-3');
        const successMessage = document.getElementById('success-message');

        const nextBtn1 = document.getElementById('next-btn-1');
        const backBtn2 = document.getElementById('back-btn-2');
        const nextBtn2 = document.getElementById('next-btn-2');
        const backBtn3 = document.getElementById('back-btn-3');
        const submitBtn = document.getElementById('submit-btn');

        const uploadArea = document.getElementById('upload-area');
        const fileInput = document.getElementById('file-input'); // This is now the WTForms-generated input
        const browseBtn = document.getElementById('browse-btn');
        const fileList = document.getElementById('file-list');
        const fileListItems = document.getElementById('file-list-items');
        const uploadProgress = document.getElementById('upload-progress');
        const progressBar = document.getElementById('progress-bar');
        const uploadPercentage = document.getElementById('upload-percentage');

        const submissionType = document.getElementById('submission_type');
        const projectTitle = document.getElementById('project_title');
        const reflectionStory = document.getElementById('reflection_story');
        const confirmationCheck = document.getElementById('confirmation_check');

        let uploadedFiles = [];
        const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50MB

        const flaskDataElement = document.getElementById('flask-data');
        const flaskData = JSON.parse(flaskDataElement.textContent);
        const { submission_type, project_title, reflection_story, confirmation_check, errors_present, has_server_errors } = flaskData;


        if (browseBtn) browseBtn.addEventListener('click', () => fileInput.click());
        if (fileInput) fileInput.addEventListener('change', handleFiles);

        if (uploadArea) {
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('border-primary', 'bg-light');
            });
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('border-primary', 'bg-light');
            });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('border-primary', 'bg-light');
                // Assign dropped files to the file input
                fileInput.files = e.dataTransfer.files;
                handleFiles({ target: fileInput });
            });
        }

        if (nextBtn1) {
            nextBtn1.addEventListener('click', () => {
                if (validateStep1()) {
                    if (step1) step1.classList.add('d-none');
                    if (step2) step2.classList.remove('d-none');
                    updateStepIndicator(2);
                }
            });
        }

        if (backBtn2) {
            backBtn2.addEventListener('click', () => {
                if (step2) step2.classList.add('d-none');
                if (step1) step1.classList.remove('d-none');
                updateStepIndicator(1);
            });
        }

        if (nextBtn2) {
            nextBtn2.addEventListener('click', () => {
                if (validateStep2()) {
                    updateReviewSection();
                    if (step2) step2.classList.add('d-none');
                    if (step3) step3.classList.remove('d-none');
                    updateStepIndicator(3);
                }
            });
        }

        if (backBtn3) {
            backBtn3.addEventListener('click', () => {
                if (step3) step3.classList.add('d-none');
                if (step2) step2.classList.remove('d-none');
                updateStepIndicator(2);
            });
        }

        if (submitBtn) {
            submitBtn.addEventListener('click', (event) => {
                if (!validateStep3()) {
                    event.preventDefault();
                }
            });
        }

        function handleFiles(event) {
            const files = Array.from(event.target.files);
            if (files.length === 0) {
                uploadedFiles = [];
                if (fileList) fileList.classList.add('d-none');
                showError('file-client-error', 'Please upload at least one file.');
                return;
            }

            uploadedFiles = [];
            if (fileListItems) fileListItems.innerHTML = '';
            let hasError = false;

            files.forEach(file => {
                if (file.size > MAX_FILE_SIZE_BYTES) {
                    showError('file-client-error', 'File too large (max 50MB): ' + file.name);
                    hasError = true;
                    return; // Skip this file, but continue processing others
                }

                const acceptedTypes = ['image/jpeg', 'image/png', 'video/mp4', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
                if (!acceptedTypes.includes(file.type)) {
                    showError('file-client-error', 'Unsupported file type: ' + file.name);
                    hasError = true;
                    return; // Skip this file
                }

                uploadedFiles.push(file);

                const fileItem = document.createElement('li');
                fileItem.className = 'd-flex align-items-center justify-content-between p-3';
                fileItem.innerHTML = `
                    <div class="d-flex align-items-center">
                        <i class="fas fa-file text-primary me-3"></i>
                        <span class="text-gray-700 text-truncate" style="max-width: 200px;">${file.name}</span>
                    </div>
                    <div class="text-gray-500 small">${formatFileSize(file.size)}</div>
                `;
                if (fileListItems) fileListItems.appendChild(fileItem);
            });

            if (uploadedFiles.length > 0 && !hasError) {
                if (fileList) fileList.classList.remove('d-none');
                hideError('file-client-error');
                simulateUpload();
            } else if (uploadedFiles.length === 0 && !hasError) {
                // No valid files were selected or all were filtered out due to errors
                if (fileList) fileList.classList.add('d-none');
                showError('file-client-error', 'Please upload at least one valid file.');
            }
        }

        function simulateUpload() {
            if (!uploadProgress) {
                console.error("Error: uploadProgress element not found.");
                return;
            }
            uploadProgress.classList.remove('d-none');
            let progress = 0;
            const interval = setInterval(() => {
                progress += Math.random() * 10;
                if (progress >= 100) {
                    progress = 100;
                    clearInterval(interval);
                }
                if (progressBar) progressBar.style.width = `${progress}%`;
                if (uploadPercentage) uploadPercentage.textContent = `${Math.round(progress)}%`;
            }, 200);
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function validateStep1() {
            let isValid = true;

            if (submissionType && !submissionType.value) {
                showError('submission-type-client-error', 'Please select how you are submitting');
                isValid = false;
            } else {
                hideError('submission-type-client-error');
            }

            // Client-side check for file presence and validity
            if (uploadedFiles.length === 0) {
                showError('file-client-error', 'Please upload at least one file');
                isValid = false;
            } else {
                hideError('file-client-error');
            }

            return isValid;
        }

        function validateStep2() {
            let isValid = true;

            if (projectTitle && !projectTitle.value.trim()) {
                showError('project-title-client-error', 'Please enter a title for your project');
                isValid = false;
            } else {
                hideError('project-title-client-error');
            }

            if (reflectionStory && (!reflectionStory.value.trim() || reflectionStory.value.trim().length < 150)) {
                showError('reflection-story-client-error', 'Please provide a detailed reflection (at least 150 characters)');
                isValid = false;
            } else {
                hideError('reflection-story-client-error');
            }

            return isValid;
        }

        function validateStep3() {
            if (confirmationCheck && !confirmationCheck.checked) {
                showError('confirmation-client-error', 'Please confirm before submitting');
                return false;
            }
            hideError('confirmation-client-error');
            return true;
        }

        function updateReviewSection() {
            const reviewTypeElement = document.getElementById('review-type');
            if (reviewTypeElement && submissionType && submissionType.options && submissionType.selectedIndex !== -1) {
                reviewTypeElement.textContent = submissionType.options[submissionType.selectedIndex].text;
            } else if (reviewTypeElement) {
                reviewTypeElement.textContent = 'N/A';
            }

            const reviewTitleElement = document.getElementById('review-title');
            if (reviewTitleElement && projectTitle) {
                reviewTitleElement.textContent = projectTitle.value;
            } else if (reviewTitleElement) {
                reviewTitleElement.textContent = 'N/A';
            }

            const reviewDescElement = document.getElementById('review-desc');
            const reviewDescLengthElement = document.getElementById('review-desc-length');
            if (reviewDescElement && reflectionStory) {
                reviewDescElement.textContent = reflectionStory.value;
            } else if (reviewDescElement) {
                reviewDescElement.textContent = 'N/A';
            }
            if (reviewDescLengthElement && reflectionStory) {
                reviewDescLengthElement.textContent = `${reflectionStory.value.length} characters`;
            } else if (reviewDescLengthElement) {
                reviewDescLengthElement.textContent = '0 characters';
            }

            const reviewFileList = document.getElementById('review-file-list');
            if (reviewFileList) {
                reviewFileList.innerHTML = '';
                uploadedFiles.forEach(file => {
                    const fileItem = document.createElement('li');
                    fileItem.className = 'd-flex align-items-center justify-content-between p-3';
                    fileItem.innerHTML = `
                        <div class="d-flex align-items-center">
                            <i class="fas fa-file text-primary me-3"></i>
                            <span class="text-gray-700">${file.name}</span>
                        </div>
                        <div class="text-gray-500 small">${formatFileSize(file.size)}</div>
                    `;
                    reviewFileList.appendChild(fileItem);
                });
            }
        }

        function updateStepIndicator(stepNumber) {
            const indicators = document.querySelectorAll('.step-indicator');

            indicators.forEach((indicator, index) => {
                const numberDiv = indicator.querySelector('.badge');
                const textSpan = indicator.querySelector('span');

                if (numberDiv && textSpan) {
                    if (index < stepNumber) {
                        numberDiv.classList.remove('bg-secondary', 'text-gray-600');
                        numberDiv.classList.add('bg-primary', 'text-white');
                        textSpan.classList.remove('text-gray-500');
                        textSpan.classList.add('text-gray-700');
                    } else {
                        numberDiv.classList.remove('bg-primary', 'text-white');
                        numberDiv.classList.add('bg-secondary', 'text-gray-600');
                        textSpan.classList.remove('text-gray-700');
                        textSpan.classList.add('text-gray-500');
                    }
                }
            });
        }

        function simulateSubmission() {
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Submitting...';
            }

            setTimeout(() => {
                if (step3) step3.classList.add('d-none');
                if (successMessage) successMessage.classList.remove('d-none');
                updateStepIndicator(4);
            }, 1500);
        }

        function showError(elementId, message) {
            const errorElement = document.getElementById(elementId);
            if (errorElement) {
                errorElement.textContent = message;
                errorElement.classList.remove('d-none');
            }
        }

        function hideError(elementId) {
            const errorElement = document.getElementById(elementId);
            if (errorElement) {
                errorElement.classList.add('d-none');
            }
        }

        // Initialize form with existing data if validation failed and page reloaded (server-side errors)
        if (has_server_errors) {
            if (submissionType) {
                submissionType.value = submission_type;
            }
            if (projectTitle) {
                projectTitle.value = project_title;
            }
            if (reflectionStory) {
                reflectionStory.value = reflection_story;
            }
            if (confirmationCheck) {
                confirmationCheck.checked = confirmation_check;
            }

            if (step1) step1.classList.add('d-none');
            if (step2) step2.classList.add('d-none');
            if (step3) step3.classList.remove('d-none');
            updateStepIndicator(3);
        }
    });
// app/static/js/challenge_wip.js

document.addEventListener('DOMContentLoaded', function() {
    const commentForm = document.getElementById('comment-form');
    if (!commentForm) return; // Exit if the form doesn't exist

    const submitBtn = document.getElementById('comment-submit-btn');
    const flaskData = JSON.parse(document.getElementById('flask-data').textContent);
    const siteKey = flaskData.recaptcha_site_key;

    if (!submitBtn || !siteKey) {
        console.error("A required element (submit button or site key) is missing. Script cannot continue.");
        return;
    }

    // --- Rate Limiting Logic (Runs on page load) ---
    const handleRateLimit = () => {
        const rateLimitInfoJSON = commentForm.dataset.rateLimitInfo;
        if (!rateLimitInfoJSON || rateLimitInfoJSON === 'null' || rateLimitInfoJSON === '{}') return;
        try {
            const rateLimitInfo = JSON.parse(rateLimitInfoJSON);
            if (rateLimitInfo && rateLimitInfo.endpoint === 'add_comment_to_wip_challenge') {
                const now = new Date().getTime() / 1000;
                const timeSince = now - rateLimitInfo.timestamp;
                if (timeSince < 60) {
                    submitBtn.disabled = true;
                    let countdown = Math.ceil(60 - timeSince);

                    const updateButtonText = () => {
                        if (countdown > 0) {
                            submitBtn.textContent = `Try again in ${countdown}s`;
                            countdown--;
                        } else {
                            submitBtn.disabled = false;
                            submitBtn.textContent = 'Submit for Review';
                            clearInterval(interval);
                        }
                    };

                    const interval = setInterval(() => {
                        updateButtonText();
                    }, 1000);
                }
            }
        } catch (e) {console.error("Error parsing rate limit info:", e);}
    };
    handleRateLimit();

    submitBtn.addEventListener('click', function() {
        if (submitBtn.disabled) return; // Ignore clicks if button is disabled by rate limit

        submitBtn.disabled = true;
        submitBtn.textContent = 'Submitting...';

        grecaptcha.ready(function() {
            grecaptcha.execute(siteKey, { action: 'comment' })
                .then(function(token) {
                    // Use FormData to easily gather all form fields, including the CSRF token
                    const formData = new FormData(commentForm);
                    
                    // Manually add the reCAPTCHA token
                    formData.set('g_recaptcha_response', token);
                    
                    // Manually add the submit button's name to satisfy `validate_on_submit()`
                    formData.set('submit', 'Submit for Review');

                    // Use the Fetch API to submit the form asynchronously
                    return fetch(commentForm.action, {
                        method: 'POST',
                        body: formData,
                        // The CSRF token is already in the formData, so no extra header is needed
                    });
                })
                .then(response => response.json()) // Parse the JSON response from the server
                .then(data => {
                    if (data.success) {
                        // On success, reload the page to see the flashed message
                        window.location.reload();
                    } else {
                        // If the server returned an error, show it in an alert
                        alert('Error: ' + (data.message || 'An unknown error occurred.'));
                        submitBtn.disabled = false;
                        submitBtn.textContent = 'Submit for Review';
                    }
                })
                .catch(function(error) {
                    console.error("Submission failed:", error);
                    alert("A network error occurred. Please check your connection and try again.");
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Submit for Review';
                });
        });
    });
});
document.addEventListener('DOMContentLoaded', function() {
    // File upload handling
    const fileInput = document.getElementById('email-file');
    const fileLabel = document.querySelector('.custom-file-label');
    const emailContent = document.getElementById('email-content');
    const form = document.getElementById('email-analysis-form');
    const loadingOverlay = document.getElementById('loading-overlay');
    
    // Update file label with selected filename
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            let fileName = '';
            if (this.files && this.files.length > 0) {
                fileName = this.files[0].name;
                
                // Read file content
                const reader = new FileReader();
                reader.onload = function(e) {
                    const content = e.target.result;
                    emailContent.value = content;
                };
                reader.readAsText(this.files[0]);
            }
            
            if (fileLabel) {
                fileLabel.textContent = fileName || 'Choose file';
            }
        });
    }
    
    // Show loading overlay when form is submitted
    if (form) {
        form.addEventListener('submit', function() {
            if (emailContent.value.trim() === '' && (!fileInput.files || fileInput.files.length === 0)) {
                alert('Please enter email content or upload an email file.');
                return false;
            }
            
            if (loadingOverlay) {
                loadingOverlay.style.display = 'flex';
            }
            return true;
        });
    }
    
    // Toggle between paste and upload methods
    const pasteModeBtn = document.getElementById('paste-mode-btn');
    const uploadModeBtn = document.getElementById('upload-mode-btn');
    const pasteSection = document.getElementById('paste-section');
    const uploadSection = document.getElementById('upload-section');
    
    if (pasteModeBtn && uploadModeBtn && pasteSection && uploadSection) {
        pasteModeBtn.addEventListener('click', function() {
            pasteSection.classList.remove('d-none');
            uploadSection.classList.add('d-none');
            pasteModeBtn.classList.add('active');
            uploadModeBtn.classList.remove('active');
        });
        
        uploadModeBtn.addEventListener('click', function() {
            pasteSection.classList.add('d-none');
            uploadSection.classList.remove('d-none');
            pasteModeBtn.classList.remove('active');
            uploadModeBtn.classList.add('active');
        });
    }
    
    // Sample email functionality
    const loadSampleBtn = document.getElementById('load-sample-btn');
    
    if (loadSampleBtn && emailContent) {
        loadSampleBtn.addEventListener('click', function() {
            const sampleEmail = `From: security@banking-secure-center.com
To: recipient@example.com
Subject: URGENT: Your account access has been limited

Dear Valued Customer,

We have detected unusual activity on your account. Your account access has been limited for security reasons.

Please verify your identity immediately by clicking the link below:

<a href="https://malicious-site.com/verify.php">https://secure.yourbank.com/verify</a>

If you do not verify your account within 24 hours, your account will be suspended.

Thank you,
Security Team
Your Bank`;

            emailContent.value = sampleEmail;
            
            // If we're in upload mode, switch to paste mode
            if (!pasteSection.classList.contains('d-none')) {
                return;
            }
            
            if (pasteModeBtn) {
                pasteModeBtn.click();
            }
        });
    }
    
    // Clear form button
    const clearFormBtn = document.getElementById('clear-form-btn');
    
    if (clearFormBtn && emailContent) {
        clearFormBtn.addEventListener('click', function() {
            emailContent.value = '';
            if (fileInput) {
                fileInput.value = '';
                if (fileLabel) {
                    fileLabel.textContent = 'Choose file';
                }
            }
        });
    }
});

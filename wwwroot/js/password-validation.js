// Password validation
function validatePassword(password) {
    // Check for uppercase
    const hasUpperCase = /[A-Z]/.test(password);
    // Check for lowercase
    const hasLowerCase = /[a-z]/.test(password);
    // Check for numbers
    const hasNumbers = /[0-9]/.test(password);
    // Check for special characters (using a simpler pattern)
    const hasSpecialChar = /[^A-Za-z0-9]/.test(password);
    // Check length
    const isLongEnough = password.length >= 8;

    return hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar && isLongEnough;
}

// Initialize password validation
document.addEventListener('DOMContentLoaded', function() {
    const newPasswordInput = document.getElementById('NewPassword');
    const confirmPasswordInput = document.getElementById('ConfirmPassword');

    if (newPasswordInput) {
        newPasswordInput.addEventListener('input', function() {
            if (!validatePassword(this.value)) {
                this.setCustomValidity('Password does not meet requirements');
            } else {
                this.setCustomValidity('');
            }
        });
    }

    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', function() {
            const newPassword = newPasswordInput.value;
            if (this.value !== newPassword) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });
    }
}); 
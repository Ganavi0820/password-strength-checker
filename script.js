/**
 * CyberShield - Password Strength Checker & Generator Script
 * Handles real-time API communication, UI state updates, and generator logic.
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const passwordInput = document.getElementById('password-input');
    const clearBtn = document.getElementById('clear-btn');
    const toggleVisibilityBtn = document.getElementById('toggle-visibility-btn');
    const eyeIcon = document.getElementById('eye-icon');
    const copyBtn = document.getElementById('copy-btn');
    
    // Meter & Labels
    const strengthText = document.getElementById('strength-text');
    const scorePill = document.getElementById('score-pill');
    const meterFill = document.getElementById('meter-fill');
    const securityBadge = document.getElementById('security-badge');
    const segments = [
        document.getElementById('seg-1'),
        document.getElementById('seg-2'),
        document.getElementById('seg-3'),
        document.getElementById('seg-4')
    ];

    // Checklist Elements
    const reqLength = document.getElementById('req-length');
    const reqUpper = document.getElementById('req-uppercase');
    const reqLower = document.getElementById('req-lowercase');
    const reqNumber = document.getElementById('req-number');
    const reqSpecial = document.getElementById('req-special');

    // Metrics & Suggestions
    const crackTimeVal = document.getElementById('crack-time-val');
    const entropyVal = document.getElementById('entropy-val');
    const suggestionsList = document.getElementById('suggestions-list');

    // Generator Elements
    const lengthSlider = document.getElementById('length-slider');
    const lengthVal = document.getElementById('length-val');
    const genUpper = document.getElementById('gen-upper');
    const genLower = document.getElementById('gen-lower');
    const genNumbers = document.getElementById('gen-numbers');
    const genSymbols = document.getElementById('gen-symbols');
    const generateBtn = document.getElementById('generate-btn');

    // Toast
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toast-message');

    let debounceTimer = null;

    // Theme Color Map
    const colorMap = {
        'None': { fill: 'var(--lvl-none)', text: 'var(--text-muted)' },
        'Weak': { fill: 'var(--lvl-weak)', text: 'var(--lvl-weak)' },
        'Fair': { fill: 'var(--lvl-fair)', text: 'var(--lvl-fair)' },
        'Medium': { fill: 'var(--lvl-medium)', text: 'var(--lvl-medium)' },
        'Strong': { fill: 'var(--lvl-strong)', text: 'var(--lvl-strong)' },
        'Very Strong': { fill: 'var(--lvl-very-strong)', text: 'var(--lvl-very-strong)' }
    };

    /**
     * Show Toast Notification
     */
    function showToast(message) {
        toastMessage.textContent = message;
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }

    /**
     * Update Checklist Item UI state
     */
    function updateCheckItem(element, isValid) {
        const iconBox = element.querySelector('.icon-box i');
        if (isValid) {
            element.classList.add('valid');
            iconBox.className = 'fa-solid fa-check';
        } else {
            element.classList.remove('valid');
            iconBox.className = 'fa-solid fa-xmark';
        }
    }

    /**
     * Update Segmented Indicators
     */
    function updateSegments(score, level) {
        let activeCount = 0;
        if (score > 0 && score <= 25) activeCount = 1;
        else if (score > 25 && score <= 50) activeCount = 2;
        else if (score > 50 && score <= 75) activeCount = 3;
        else if (score > 75) activeCount = 4;

        let activeColor = colorMap[level] ? colorMap[level].fill : 'var(--lvl-none)';

        segments.forEach((seg, index) => {
            if (index < activeCount) {
                seg.style.backgroundColor = activeColor;
            } else {
                seg.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
            }
        });
    }

    /**
     * Render UI based on API evaluation response
     */
    function updateUI(data) {
        const { score, level, label, entropy, crack_time, checks, suggestions, is_common } = data;

        // 1. Text & Score Pill
        strengthText.textContent = label || level || 'None';
        scorePill.textContent = `Score: ${score} / 100`;

        const styleConfig = colorMap[level] || colorMap['None'];
        strengthText.style.color = styleConfig.text;
        securityBadge.textContent = level === 'None' ? 'Waiting for input' : label;
        securityBadge.style.color = styleConfig.text;
        securityBadge.style.borderColor = styleConfig.fill;

        // 2. Meter Fill
        meterFill.style.width = `${score}%`;
        meterFill.style.backgroundColor = styleConfig.fill;

        // 3. Segmented Bar
        updateSegments(score, level);

        // 4. Checklist Items
        updateCheckItem(reqLength, checks.length);
        updateCheckItem(reqUpper, checks.uppercase);
        updateCheckItem(reqLower, checks.lowercase);
        updateCheckItem(reqNumber, checks.number);
        updateCheckItem(reqSpecial, checks.special);

        // 5. Security Metrics
        crackTimeVal.textContent = crack_time || 'Instant';
        entropyVal.textContent = `${entropy || 0} bits`;

        // 6. Suggestions List
        suggestionsList.innerHTML = '';
        if (suggestions && suggestions.length > 0) {
            suggestions.forEach(item => {
                const li = document.createElement('li');
                if (level === 'Strong' || level === 'Very Strong') {
                    li.className = 'suggestion-item success-item';
                    li.innerHTML = `<i class="fa-solid fa-circle-check"></i> ${item}`;
                } else if (is_common) {
                    li.className = 'suggestion-item';
                    li.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${item}`;
                } else {
                    li.className = 'suggestion-item';
                    li.innerHTML = `<i class="fa-solid fa-circle-notch"></i> ${item}`;
                }
                suggestionsList.appendChild(li);
            });
        }
    }

    /**
     * Client-side fast local evaluation fallback
     */
    function evaluateLocal(password) {
        if (!password) {
            return {
                score: 0,
                level: 'None',
                label: 'Enter a password',
                entropy: 0,
                crack_time: 'Instant',
                checks: { length: false, uppercase: false, lowercase: false, number: false, special: false },
                suggestions: ['Type a password to check its strength.'],
                is_common: false
            };
        }

        const len = password.length;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNum = /[0-9]/.test(password);
        const hasSpec = /[^A-Za-z0-9]/.test(password);

        let score = 0;
        if (len >= 16) score += 40;
        else if (len >= 12) score += 30;
        else if (len >= 8) score += 20;
        else score += 10;

        const variety = [hasUpper, hasLower, hasNum, hasSpec].filter(Boolean).length;
        score += variety * 10;

        let level = 'Weak';
        if (score >= 75) level = 'Strong';
        else if (score >= 45) level = 'Medium';

        return {
            score: Math.min(100, score),
            level: level,
            label: level,
            entropy: Math.round(len * 4.5 * 10) / 10,
            crack_time: score > 70 ? 'Years+' : 'Hours',
            checks: {
                length: len >= 8,
                uppercase: hasUpper,
                lowercase: hasLower,
                number: hasNum,
                special: hasSpec
            },
            suggestions: ['Evaluating backend analysis...'],
            is_common: false
        };
    }

    /**
     * Send password to Flask API endpoint
     */
    async function checkPasswordAPI(password) {
        if (!password) {
            updateUI(evaluateLocal(''));
            return;
        }

        // Instant local preview update
        updateUI(evaluateLocal(password));

        try {
            const response = await fetch('/api/check-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });

            if (response.ok) {
                const data = await response.json();
                updateUI(data);
            }
        } catch (error) {
            console.error('API Check Error:', error);
        }
    }

    // Input Event Handler (with Debounce)
    passwordInput.addEventListener('input', (e) => {
        const val = e.target.value;
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            checkPasswordAPI(val);
        }, 150);
    });

    // Clear Input Button
    clearBtn.addEventListener('click', () => {
        passwordInput.value = '';
        passwordInput.focus();
        checkPasswordAPI('');
    });

    // Toggle Password Visibility
    toggleVisibilityBtn.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        eyeIcon.className = isPassword ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
    });

    // Copy Password Button
    copyBtn.addEventListener('click', async () => {
        const text = passwordInput.value;
        if (!text) {
            showToast('Nothing to copy!');
            return;
        }

        try {
            await navigator.clipboard.writeText(text);
            copyBtn.classList.add('show-tooltip');
            showToast('Password copied to clipboard!');
            setTimeout(() => copyBtn.classList.remove('show-tooltip'), 2000);
        } catch (err) {
            // Fallback for older browsers
            passwordInput.select();
            document.execCommand('copy');
            showToast('Password copied to clipboard!');
        }
    });

    // Generator Length Slider
    lengthSlider.addEventListener('input', (e) => {
        lengthVal.textContent = e.target.value;
    });

    // Generate Password Button Event
    generateBtn.addEventListener('click', async () => {
        const payload = {
            length: parseInt(lengthSlider.value),
            uppercase: genUpper.checked,
            lowercase: genLower.checked,
            numbers: genNumbers.checked,
            symbols: genSymbols.checked
        };

        try {
            const response = await fetch('/api/generate-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const data = await response.json();
                passwordInput.value = data.generated_password;
                passwordInput.type = 'text';
                eyeIcon.className = 'fa-solid fa-eye-slash';
                
                if (data.analysis) {
                    updateUI(data.analysis);
                } else {
                    checkPasswordAPI(data.generated_password);
                }

                showToast('New strong password generated!');
            }
        } catch (err) {
            console.error('Generator Error:', err);
            showToast('Failed to generate password.');
        }
    });

    // Initialize with empty input
    checkPasswordAPI('');
});

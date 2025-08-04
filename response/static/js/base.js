// Mobile menu toggle
document.addEventListener('DOMContentLoaded', function() {
    const mobileMenu = document.getElementById('mobile-menu');
    const navbarMenu = document.querySelector('.navbar-menu');
    
    if (mobileMenu) {
        mobileMenu.addEventListener('click', function() {
            mobileMenu.classList.toggle('active');
            navbarMenu.classList.toggle('active');
        });
    }

    const increaseFontBtn = document.getElementById('increase-font');
    const decreaseFontBtn = document.getElementById('decrease-font');
    const resetFontBtn = document.getElementById('reset-font');
    const body = document.body;

    if (increaseFontBtn) {
        increaseFontBtn.addEventListener('click', function() {
            let currentSize = parseFloat(window.getComputedStyle(body, null).getPropertyValue('font-size'));
            body.style.fontSize = (currentSize + 20) + 'px';
        });
    }

    if (decreaseFontBtn) {
        decreaseFontBtn.addEventListener('click', function() {
            let currentSize = parseFloat(window.getComputedStyle(body, null).getPropertyValue('font-size'));
            body.style.fontSize = (currentSize - 20) + 'px';
        });
    }

    if (resetFontBtn) {
        resetFontBtn.addEventListener('click', function() {
            body.style.fontSize = ''; 
        });
    }
});


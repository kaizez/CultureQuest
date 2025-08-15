document.addEventListener('DOMContentLoaded', function () {

    // --- Tour for the Challenge Hub Page ---
    function startChallengeHubTour() {
        introJs().setOptions({
            steps: [{
                title: 'Welcome to the Challenge Hub!',
                intro: 'This is where you can find new challenges, track your progress, and see completed ones.'
            }, {
                element: document.querySelector('#challengeTabs'),
                title: 'Challenge Categories',
                intro: 'Use these tabs to switch between New Challenges, your accepted challenges (My Challenges), and ones you have already completed.',
                position: 'bottom'
            }, {
                element: document.querySelector('#new-challenges .challenge-card'),
                title: 'Viewing a Challenge',
                intro: 'Click on any challenge card to see more details and accept it.',
                position: 'top'
            }]
        }).start();
    }

    // --- Tour for the Challenge Description Page ---
    function startChallengeDescriptionTour() {
        introJs().setOptions({
            steps: [{
                title: 'Welcome!',
                intro: 'This is the challenge description page. Let\'s take a quick look around.'
            }, {
                element: document.querySelector('#completion_criteria'),
                title: 'Completion Criteria',
                intro: 'This list shows you exactly what you need to do to complete the challenge.',
                position: 'bottom'
            }, {
                element: document.querySelector('#accept-challenge-btn'),
                title: 'Accept Challenge',
                intro: 'When you are ready, click here to accept the challenge and add it to your "My Challenges" list.',
                position: 'bottom'
            }]
        }).start();
    }

    // --- Tour for the Work-in-Progress (WIP) Page (Corrected) ---
    function startWipPageTour() {
        introJs().setOptions({
            steps: [{
                title: 'Work In Progress!',
                intro: 'This page helps you track your active challenges.'
            }, {
                // This targets the status card in the right column
                element: document.querySelector('.col-lg-4 .card'),
                title: 'Track Your Status',
                intro: 'Keep an eye on your progress and points here. You can also chat with others or move on to the final submission.',
                position: 'left'
            }, {
                // This targets the community discussion section
                element: document.querySelector('.card:has(.fa-comments)'),
                title: 'Community Discussion',
                intro: 'Ask questions, share tips, or see what others are saying about this challenge.',
                position: 'top'
            }, {
                // This targets the "Submit Challenge" button
                element: document.querySelector('.btn-success'),
                title: 'Final Submission',
                intro: 'When you have fulfilled all the criteria, click here to go to the final submission page!',
                position: 'left'
            }]
        }).start();
    }

    // --- Logic to Attach Tours to Buttons ---

    const hubTourButton = document.getElementById('start-tour-btn');
    if (hubTourButton) {
        hubTourButton.addEventListener('click', function(e) {
            e.preventDefault();
            startChallengeHubTour();
        });
    }

    const descTourButton = document.getElementById('start-desc-tour-btn');
    if (descTourButton) {
        descTourButton.addEventListener('click', function(e) {
            e.preventDefault();
            startChallengeDescriptionTour();
        });
    }

    const wipTourButton = document.getElementById('start-wip-tour-btn');
    if (wipTourButton) {
        wipTourButton.addEventListener('click', function(e) {
            e.preventDefault();
            startWipPageTour();
        });
    }
});
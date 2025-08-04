document.addEventListener('DOMContentLoaded', function () {
    // Function to start the tour on the main Challenges Hub page
    const startHubTour = () => {
        const intro = introJs();
        intro.setOptions({
            steps: [
                {
                    title: 'Welcome!',
                    intro: 'Welcome to the Challenges Hub! Let us show you around.'
                },
                {
                    element: document.querySelector('#challengeTabs'),
                    title: 'Challenge Categories',
                    intro: 'You can switch between New, In Progress (My Challenges), and Completed challenges here.',
                    position: 'bottom'
                },
                {
                    element: document.querySelector('.challenge-card'),
                    title: 'Challenge Cards',
                    intro: 'Each challenge is displayed on a card like this, showing its title and difficulty.',
                    position: 'top'
                },
                {
                    element: document.querySelector('.challenge-card .btn-primary'),
                    title: 'View Details',
                    intro: 'When you find a challenge you like, click this button to see more details and get started!',
                    position: 'top'
                }
            ],
            showProgress: true,
            showBullets: false,
            exitOnOverlayClick: false
        });
        intro.start();
    };

    // Function to start the tour on the Challenge Description page
    const startDescriptionTour = () => {
        const intro = introJs();
        intro.setOptions({
            steps: [
                {
                    title: 'Challenge Details',
                    intro: 'This page gives you all the details about a specific challenge.'
                },
                {
                    element: document.querySelector('#accept-challenge-btn'),
                    title: 'Accept the Challenge',
                    intro: 'When you are ready, click here to accept the challenge and add it to "My Challenges"!',
                    position: 'bottom'
                }
            ]
        });
        intro.start();
    };

    // --- Event Listeners ---
    const hubTourButton = document.getElementById('start-hub-tour-btn');
    const descriptionTourButton = document.getElementById('start-description-tour-btn');

    if (hubTourButton) {
        hubTourButton.addEventListener('click', startHubTour);
    }
    if (descriptionTourButton) {
        descriptionTourButton.addEventListener('click', startDescriptionTour);
    }
});
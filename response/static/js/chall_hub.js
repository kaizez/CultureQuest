document.addEventListener('DOMContentLoaded', () => {
    const searchBar = document.getElementById('search-bar');
    const challengeTabs = document.querySelectorAll('#challengeTabs .nav-link');

    // This function performs the search and filtering
    function applyFilters() {
        const searchQuery = searchBar.value.toLowerCase();
        
        // Find the currently active tab pane
        const activeTabPane = document.querySelector('.tab-pane.fade.show.active');
        if (!activeTabPane) {
            return; // Exit if no active tab is found
        }
        
        // Get all challenge columns within that active tab
        const challenges = activeTabPane.querySelectorAll('.col');
        let visibleChallengeCount = 0;

        challenges.forEach(col => {
            const card = col.querySelector('.challenge-card');
            if (card) {
                const title = card.dataset.title.toLowerCase();
                
                // If the card's title includes the search query...
                if (title.includes(searchQuery)) {
                    // ...show the column by removing the 'd-none' class.
                    col.classList.remove('d-none');
                    visibleChallengeCount++;
                } else {
                    // ...otherwise, hide the column by adding the 'd-none' class.
                    col.classList.add('d-none');
                }
            }
        });

        // Optional: Show a "no results" message if needed
        const noResultsMessage = activeTabPane.querySelector('.text-secondary.text-center.col-12');
        if (noResultsMessage) {
            if (visibleChallengeCount === 0) {
                noResultsMessage.textContent = 'No challenges match your search.';
                noResultsMessage.classList.remove('d-none');
            } else {
                noResultsMessage.classList.add('d-none');
            }
        }
    }

    // Add an event listener to the search bar
    if (searchBar) {
        searchBar.addEventListener('input', applyFilters);
    }

    // Add event listeners to the tabs to re-apply the filter when a new tab is shown
    challengeTabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', applyFilters);
    });

    // Run once on page load to handle any initial state
    applyFilters();
});
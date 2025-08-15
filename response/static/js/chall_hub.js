// static/js/chall_hub.js
document.addEventListener('DOMContentLoaded', () => {
    const newTabBtn = document.getElementById('new-tab');
    const currentTabBtn = document.getElementById('current-tab');
    const doneTabBtn = document.getElementById('done-tab');

    const newChallengesContainer = document.getElementById('new-challenges-tab');
    const currentChallengesContainer = document.getElementById('current-challenges-tab');
    const doneChallengesContainer = document.getElementById('done-challenges-tab');

    const searchBar = document.getElementById('search-bar');
    const sortBy = document.getElementById('sort-by');
    const emptyState = document.getElementById('empty-state');
    const resetButton = document.getElementById('reset-filters-btn');

    let allNewChallenges = [];
    let allCurrentChallenges = [];
    let allDoneChallenges = [];

    function updateChallengeLists() {
        allNewChallenges = Array.from(newChallengesContainer.querySelectorAll('.challenge-card')).map(card => card.closest('.col'));
        allCurrentChallenges = Array.from(currentChallengesContainer.querySelectorAll('.challenge-card')).map(card => card.closest('.col'));
        allDoneChallenges = Array.from(doneChallengesContainer.querySelectorAll('.challenge-card')).map(card => card.closest('.col'));
    }

    if (newTabBtn) newTabBtn.addEventListener('shown.bs.tab', applyFiltersAndSort);
    if (currentTabBtn) currentTabBtn.addEventListener('shown.bs.tab', applyFiltersAndSort);
    if (doneTabBtn) doneTabBtn.addEventListener('shown.bs.tab', applyFiltersAndSort);

    if (searchBar) searchBar.addEventListener('input', applyFiltersAndSort);
    
    if (resetButton) {
        resetButton.addEventListener('click', () => {
            if(searchBar) searchBar.value = '';
            applyFiltersAndSort();
        });
    }

    function applyFiltersAndSort() {
        updateChallengeLists();

        const searchQuery = searchBar ? searchBar.value.toLowerCase() : '';
        
        let challengesToFilter = [];
        let activeContainerElement = null;

        if (newChallengesContainer && newChallengesContainer.classList.contains('show')) {
            challengesToFilter = allNewChallenges;
            activeContainerElement = newChallengesContainer.querySelector('.row');
        } else if (currentChallengesContainer && currentChallengesContainer.classList.contains('show')) {
            challengesToFilter = allCurrentChallenges;
            activeContainerElement = currentChallengesContainer.querySelector('.row');
        } else if (doneChallengesContainer && doneChallengesContainer.classList.contains('show')) {
            challengesToFilter = allDoneChallenges;
            activeContainerElement = doneChallengesContainer.querySelector('.row');
        } else {
            // Fallback to the first tab if none are active
            challengesToFilter = allNewChallenges;
            activeContainerElement = newChallengesContainer ? newChallengesContainer.querySelector('.row') : null;
        }

        let filteredChallenges = challengesToFilter.filter(colElement => {
            const card = colElement.querySelector('.challenge-card');
            if (!card) return false;

            const title = card.dataset.title ? card.dataset.title.toLowerCase() : '';
            
            const matchesSearch = title.includes(searchQuery);
            
            return matchesSearch;
        });

        
        if (activeContainerElement) {
            activeContainerElement.innerHTML = '';
            if (filteredChallenges.length > 0) {
                filteredChallenges.forEach(colElement => activeContainerElement.appendChild(colElement));
                if (emptyState) emptyState.classList.add('d-none');
            } else {
                if (emptyState) emptyState.classList.remove('d-none');
            }
        }
    }
    
    updateChallengeLists();
    applyFiltersAndSort();
});
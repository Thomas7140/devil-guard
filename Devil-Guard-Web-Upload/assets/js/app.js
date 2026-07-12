"use strict";

for (const element of document.querySelectorAll('[data-confirm]')) {
  element.addEventListener('click', event => {
    if (!window.confirm(element.getAttribute('data-confirm') || 'Continue?')) {
      event.preventDefault();
    }
  });
}

const statusTarget = document.querySelector('[data-api-status]');
if (statusTarget) {
  fetch('./api/v1/status', {headers: {'Accept': 'application/json'}})
    .then(response => response.ok ? response.json() : Promise.reject())
    .then(data => { statusTarget.textContent = data.status || 'online'; })
    .catch(() => { statusTarget.textContent = 'unavailable'; statusTarget.classList.add('danger'); });
}

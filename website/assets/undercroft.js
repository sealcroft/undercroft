// Adds a "Μ" button in the menu bar linking back to the landing page
// (the book is served under /docs/, so ../ is the site root).
(function () {
  var bar = document.querySelector('.left-buttons');
  if (!bar) return;
  var a = document.createElement('a');
  a.href = '../';
  a.className = 'mnemo-home';
  a.title = 'Undercroft — home';
  a.setAttribute('aria-label', 'Undercroft home');
  a.textContent = 'Μ';
  bar.appendChild(a);
})();

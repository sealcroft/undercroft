// mdBook's head bootstrap force-hides the sidebar on every page load when
// the window is under 1080px — even right after the reader opened it — so
// each click in the menu re-collapses it. Restore the reader's last
// explicit choice (mdBook records it in localStorage on every toggle),
// except on phone-width screens where the overlay would cover the text.
(function () {
  var toggle = document.getElementById('mdbook-sidebar-toggle-anchor');
  if (!toggle || toggle.checked) {
    return;
  }
  var saved = null;
  try { saved = localStorage.getItem('mdbook-sidebar'); } catch (e) { /* ignore */ }
  if (saved === 'visible' && document.body.clientWidth >= 600) {
    // book.js has already run: it saw the hidden state and set an inline
    // display:none on the sidebar (its anti-Ctrl-F measure), so flipping
    // the class alone leaves an invisible sidebar. Undo the display, then
    // drive book.js's own show path via the checkbox change event
    // (restores the class, aria state, and link tab order).
    var sidebar = document.getElementById('mdbook-sidebar');
    if (sidebar) {
      sidebar.style.display = '';
    }
    document.documentElement.classList.add('sidebar-visible');
    toggle.checked = true;
    toggle.dispatchEvent(new Event('change'));
  }
})();

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

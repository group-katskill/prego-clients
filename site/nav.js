// The Artifacts menu of the top navigation. The menu is a <details> disclosure, so it opens and closes without
// JavaScript, and screen readers announce its open state from <summary>. This file only adds:
// - Escape closes the menu and puts the focus back on its summary;
// - a click outside the menu closes it;
// - the menu closes when the focus leaves it (Tab past the last item) and after a link in it is followed.
// An external file, so the CSP needs no inline script.
(function () {
  document.addEventListener("DOMContentLoaded", function () {
    var menus = document.querySelectorAll("details.nav-menu");
    Array.prototype.forEach.call(menus, function (menu) {
      var summary = menu.querySelector("summary");

      menu.addEventListener("keydown", function (e) {
        if ((e.key === "Escape" || e.key === "Esc") && menu.open) {
          menu.open = false;
          if (summary) summary.focus();
          e.preventDefault();
        }
      });

      menu.addEventListener("focusout", function (e) {
        if (menu.open && e.relatedTarget && !menu.contains(e.relatedTarget)) {
          menu.open = false;
        }
      });

      menu.addEventListener("click", function (e) {
        var link = e.target.closest ? e.target.closest("a") : null;
        if (link && menu.contains(link)) menu.open = false;
      });

      document.addEventListener("click", function (e) {
        if (menu.open && !menu.contains(e.target)) menu.open = false;
      });
    });
  });
})();

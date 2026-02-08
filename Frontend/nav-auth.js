(function () {
  const DEFAULT_VIEWER_MESSAGE = "Accès réservé";

  function getNextTarget() {
    const page = location.pathname.split("/").pop() || "dashboard.html";
    return page + location.search + location.hash;
  }

  function getLoginHref() {
    return "login.html?next=" + encodeURIComponent(getNextTarget());
  }

  function highlightActive() {
    const links = document.querySelectorAll(".topnav a[href]");
    const path = location.pathname.split("/").pop();
    links.forEach((a) => {
      const href = a.getAttribute("href");
      if (href && href === path) a.classList.add("active");
    });
  }

  function applyNavRole(role) {
    const loginBtn = document.getElementById("nav-login");
    const logoutBtn = document.getElementById("nav-logout");
    const createLink = document.getElementById("link-create-centre");
    const usersLink = document.getElementById("link-users");
    const settingsLink = document.getElementById("link-settings");

    const isViewer = !role || role === "viewer";
    if (loginBtn) loginBtn.style.display = isViewer ? "inline" : "none";
    if (logoutBtn) logoutBtn.style.display = isViewer ? "none" : "inline";
    if (createLink) createLink.style.display = isViewer ? "none" : "inline";
    if (usersLink) usersLink.style.display = role === "admin" ? "inline" : "none";
    if (settingsLink) settingsLink.style.display = role === "admin" ? "inline" : "none";
  }

  async function resolveRole() {
    const token = localStorage.getItem("token");
    if (!token) return null;
    try {
      const res = await fetch("/me", {
        headers: { Authorization: "Bearer " + token }
      });
      if (!res.ok) throw new Error("unauthorized");
      const user = await res.json().catch(() => null);
      return user && user.role ? user.role : null;
    } catch (e) {
      localStorage.removeItem("token");
      return null;
    }
  }

  function showAccessDenied(message) {
    const msg = message || DEFAULT_VIEWER_MESSAGE;
    const page = document.querySelector(".page");
    if (page) {
      page.innerHTML =
        '<div class="card" style="max-width:520px;margin:16px auto;text-align:center;">' +
        msg +
        "</div>";
      return;
    }
    alert(msg);
  }

  async function loadNav() {
    const holder = document.getElementById("nav-placeholder");
    if (holder) {
      try {
        const res = await fetch("nav.html");
        if (!res.ok) throw new Error("nav_load_failed");
        const html = await res.text();
        holder.innerHTML = html;
      } catch (e) {
        // If nav fails to load, continue without it
      }
    }

    const loginBtn = document.getElementById("nav-login");
    if (loginBtn) loginBtn.setAttribute("href", getLoginHref());

    const logoutBtn = document.getElementById("nav-logout");
    if (logoutBtn && !logoutBtn.dataset.bound) {
      logoutBtn.dataset.bound = "1";
      logoutBtn.addEventListener("click", function (e) {
        e.preventDefault();
        localStorage.removeItem("token");
        location.href = getLoginHref();
      });
    }

    highlightActive();
    const role = await resolveRole();
    applyNavRole(role);
    return role;
  }

  window.initNavAuth = async function (options) {
    const opts = options || {};
    const role = await loadNav();
    const token = localStorage.getItem("token");

    if (opts.requireAuth && !token) {
      location.href = getLoginHref();
      return { role: null };
    }

    const effectiveRole = role || "viewer";
    if (opts.allowViewer === false && effectiveRole === "viewer") {
      if (typeof opts.onViewerDenied === "function") {
        opts.onViewerDenied();
      } else {
        showAccessDenied(opts.viewerMessage);
      }
    }

    return { role };
  };
})();

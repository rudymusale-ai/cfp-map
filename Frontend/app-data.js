(function () {
  const API_URL = "https://cfp-map-production-232a.up.railway.app";
  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
  if (typeof window !== "undefined") {
    window.escapeHtml = escapeHtml;
  }
  // Automatically attach JWT to same-origin API calls
  if (typeof window !== "undefined" && window.fetch && !window.__authFetchWrapped) {
    const originalFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      const options = init ? { ...init } : {};
      const headers = new Headers(options.headers || {});
      const token = localStorage.getItem("token");

      let url = "";
      if (typeof input === "string") url = input;
      else if (input && input.url) url = input.url;

      const isRelative = url.startsWith("/");
      const isSameOrigin = !url.startsWith("http://") && !url.startsWith("https://");
      const isApiAbsolute = url.startsWith(API_URL);
      const isLiveServer = (location.port === "5500");
      const apiPrefixes = [
        "/auth",
        "/me",
        "/centres",
        "/users",
        "/settings",
        "/stats",
        "/logs",
        "/rapports",
        "/update-cycle",
        "/dashboard-data",
        "/health"
      ];
      const isApiCall = isRelative && apiPrefixes.some(p => url.startsWith(p));
      if (isLiveServer && isApiCall) {
        url = API_URL + url;
      }

      if ((isRelative || isSameOrigin || isApiAbsolute) && token && !headers.has("Authorization")) {
        headers.set("Authorization", "Bearer " + token);
      }

      options.headers = headers;
      return originalFetch(url || input, options);
    };
    window.__authFetchWrapped = true;

    // Live Server banner
    if (location.port === "5500" && !document.getElementById("live-server-banner")) {
      const banner = document.createElement("div");
      banner.id = "live-server-banner";
      banner.style.cssText = "position:fixed;bottom:12px;right:12px;background:#111827;color:#fff;padding:8px 10px;border-radius:8px;font-size:12px;z-index:9999;opacity:.9;display:flex;gap:8px;align-items:center";

      const text = document.createElement("span");
      text.textContent = "Mode Live Server : API -> " + API_URL;

      const closeBtn = document.createElement("button");
      closeBtn.type = "button";
      closeBtn.textContent = "Masquer";
      closeBtn.style.cssText = "background:#374151;color:#fff;border:none;border-radius:6px;padding:4px 8px;font-size:11px;cursor:pointer";
      closeBtn.addEventListener("click", () => banner.remove());

      banner.appendChild(text);
      banner.appendChild(closeBtn);

      document.addEventListener("DOMContentLoaded", () => {
        document.body.appendChild(banner);
      });
    }
  }
  const STORAGE_KEY = "cfp_app_data_v1";

  const DEFAULT_DATA = {
    centres: [
      {
        id: 1,
        nom: "CFP Kinshasa",
        type: "public",
        sousdivision: "Kinshasa",
        filieres: ["Informatique", "Mécanique"],
        filiere: "Informatique",
        statut: "Actif",
        capacite: 220,
        lat: -4.325,
        lng: 15.322,
        adresse: "Gombe, Kinshasa"
      },
      {
        id: 2,
        nom: "CFP Goma",
        type: "prive",
        sousdivision: "Goma",
        filieres: ["Agriculture", "Informatique"],
        filiere: "Agriculture",
        statut: "Actif",
        capacite: 140,
        lat: -1.658,
        lng: 29.221,
        adresse: "Quartier Katindo, Goma"
      },
      {
        id: 3,
        nom: "CFP Lubumbashi",
        type: "public",
        sousdivision: "Lubumbashi",
        filieres: ["Mécanique"],
        filiere: "Mécanique",
        statut: "Actif",
        capacite: 180,
        lat: -11.664,
        lng: 27.479,
        adresse: "Centre-ville, Lubumbashi"
      }
    ],
    users: [
      { id: 1, nom: "Admin", role: "admin", email: "admin@cfp.local", statut: "Actif" },
      { id: 2, nom: "Superviseur", role: "superviseur", email: "superviseur@cfp.local", statut: "Actif" }
    ],
    settings: {
      filieres: [
        { id: 1, nom: "Informatique" },
        { id: 2, nom: "Agriculture" },
        { id: 3, nom: "Mécanique" }
      ],
      sousdivisions: [
        { id: 1, nom: "Kinshasa" },
        { id: 2, nom: "Goma" },
        { id: 3, nom: "Lubumbashi" }
      ],
      equipements: [
        { id: 1, nom: "Atelier" },
        { id: 2, nom: "Ordinateurs" },
        { id: 3, nom: "Eau" },
        { id: 4, nom: "Électricité" }
      ]
    },
    year: 2026,
    cycle: 1,
    logs: [
      { id: 1, user: "system", action: "INIT", target: "data", date: new Date().toISOString() }
    ]
  };

  function clone(obj) {
    if (typeof structuredClone === "function") return structuredClone(obj);
    return JSON.parse(JSON.stringify(obj));
  }

  function readData() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return clone(DEFAULT_DATA);
      const parsed = JSON.parse(raw);
      return mergeDefaults(parsed, DEFAULT_DATA);
    } catch (e) {
      return clone(DEFAULT_DATA);
    }
  }

  function writeData(data) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }

  function mergeDefaults(current, defaults) {
    const merged = clone(defaults);
    if (current && typeof current === "object") {
      Object.keys(defaults).forEach((k) => {
        if (current[k] !== undefined) merged[k] = current[k];
      });
    }
    return merged;
  }

  function nextId(list) {
    return list.reduce((m, e) => Math.max(m, e.id || 0), 0) + 1;
  }

  function logAction(data, action, target, user) {
    data.logs.push({
      id: nextId(data.logs),
      user: user || "system",
      action,
      target,
      date: new Date().toISOString()
    });
  }

  function getCentres() {
    return readData().centres.slice();
  }

  function getCentre(id) {
    const data = readData();
    return data.centres.find((c) => String(c.id) === String(id)) || null;
  }

  function addCentre(payload) {
    const data = readData();
    const centre = {
      id: nextId(data.centres),
      nom: payload.nom || "Centre",
      type: payload.type || "public",
      sousdivision: payload.sousdivision || "N/A",
      filieres: payload.filieres || [],
      filiere: payload.filiere || (payload.filieres && payload.filieres[0]) || "",
      statut: payload.statut || "Actif",
      capacite: Number(payload.capacite || 0),
      lat: Number(payload.lat || 0),
      lng: Number(payload.lng || 0),
      adresse: payload.adresse || ""
    };
    data.centres.push(centre);
    logAction(data, "CREATE", "centre:" + centre.nom, "local");
    writeData(data);
    return centre;
  }

  function updateCentre(id, updates) {
    const data = readData();
    const centre = data.centres.find((c) => String(c.id) === String(id));
    if (!centre) return null;
    Object.assign(centre, updates);
    logAction(data, "UPDATE", "centre:" + centre.nom, "local");
    writeData(data);
    return centre;
  }

  function deleteCentre(id) {
    const data = readData();
    const idx = data.centres.findIndex((c) => String(c.id) === String(id));
    if (idx === -1) return false;
    const removed = data.centres.splice(idx, 1)[0];
    logAction(data, "DELETE", "centre:" + removed.nom, "local");
    writeData(data);
    return true;
  }

  function getUsers() {
    return readData().users.slice();
  }

  function addUser(payload) {
    const data = readData();
    const user = {
      id: nextId(data.users),
      nom: payload.nom || "Utilisateur",
      role: payload.role || "viewer",
      email: payload.email || "user@cfp.local",
      statut: "Actif"
    };
    data.users.push(user);
    logAction(data, "CREATE", "user:" + user.email, "local");
    writeData(data);
    return user;
  }

  function updateUser(id, updates) {
    const data = readData();
    const user = data.users.find((u) => String(u.id) === String(id));
    if (!user) return null;
    Object.assign(user, updates);
    logAction(data, "UPDATE", "user:" + user.email, "local");
    writeData(data);
    return user;
  }

  function disableUser(id) {
    return updateUser(id, { statut: "Desactive" });
  }

  function deleteUser(id) {
    const data = readData();
    const idx = data.users.findIndex((u) => String(u.id) === String(id));
    if (idx === -1) return false;
    const removed = data.users.splice(idx, 1)[0];
    logAction(data, "DELETE", "user:" + removed.email, "local");
    writeData(data);
    return true;
  }

  function getSettings(type) {
    const data = readData();
    const list = data.settings[type] || [];
    return list.slice();
  }

  function addSetting(type, nom) {
    const data = readData();
    if (!data.settings[type]) data.settings[type] = [];
    const item = { id: nextId(data.settings[type]), nom };
    data.settings[type].push(item);
    logAction(data, "CREATE", "setting:" + type + ":" + nom, "local");
    writeData(data);
    return item;
  }

  function deleteSetting(type, id) {
    const data = readData();
    if (!data.settings[type]) return false;
    const idx = data.settings[type].findIndex((e) => String(e.id) === String(id));
    if (idx === -1) return false;
    const removed = data.settings[type].splice(idx, 1)[0];
    logAction(data, "DELETE", "setting:" + type + ":" + removed.nom, "local");
    writeData(data);
    return true;
  }

  function getYear() {
    return readData().year;
  }

  function setYear(year) {
    const data = readData();
    data.year = Number(year || data.year);
    logAction(data, "UPDATE", "year:" + data.year, "local");
    writeData(data);
    return data.year;
  }

  function incrementCycle() {
    const data = readData();
    data.cycle += 1;
    logAction(data, "UPDATE", "cycle:" + data.cycle, "local");
    writeData(data);
    return data.cycle;
  }

  function getDashboardData() {
    const centres = getCentres();
    const total = centres.length;
    const pub = centres.filter((c) => c.type === "public").length;
    const prive = centres.filter((c) => c.type === "prive").length;
    return {
      total,
      public: pub,
      private: prive,
      updated: new Date().toLocaleDateString()
    };
  }

  function getStatsData(filters) {
    const centres = getCentres().filter((c) => {
      if (filters && filters.sousdivision && c.sousdivision !== filters.sousdivision) return false;
      return true;
    });

    const byTerr = {};
    centres.forEach((c) => {
      byTerr[c.sousdivision] = (byTerr[c.sousdivision] || 0) + 1;
    });

    const byFil = {};
    centres.forEach((c) => {
      (c.filieres || []).forEach((f) => {
        byFil[f] = (byFil[f] || 0) + 1;
      });
    });

    const capLabels = centres.map((c) => c.nom);
    const capValues = centres.map((c) => c.capacite || 0);

    const settings = getSettings("sousdivisions");
    const zones = settings
      .map((s) => s.nom)
      .filter((s) => !centres.some((c) => c.sousdivision === s));

    return {
      territoires: { labels: Object.keys(byTerr), values: Object.values(byTerr) },
      public: centres.filter((c) => c.type === "public").length,
      prive: centres.filter((c) => c.type === "prive").length,
      filieres: { labels: Object.keys(byFil), values: Object.values(byFil) },
      capacites: { labels: capLabels, values: capValues },
      zones
    };
  }

  function getLogs(filters) {
    const data = readData();
    return data.logs.filter((l) => {
      if (filters.user && !l.user.toLowerCase().includes(filters.user.toLowerCase())) return false;
      if (filters.action && l.action !== filters.action) return false;
      if (filters.date) {
        const d = new Date(l.date).toISOString().slice(0, 10);
        if (d !== filters.date) return false;
      }
      return true;
    });
  }

  function generateReportHtml(options) {
    const centres = getCentres().filter((c) => {
      if (options.type === "sousdivision" && options.sousdivision) {
        return c.sousdivision === options.sousdivision;
      }
      if (options.type === "filiere" && options.filiere) {
        return (c.filieres || []).includes(options.filiere);
      }
      return true;
    });

    const esc = escapeHtml;
    const rows = centres
      .map(
        (c) =>
          "<tr><td>" +
          esc(c.nom) +
          "</td><td>" +
          esc(c.type) +
          "</td><td>" +
          esc(c.sousdivision) +
          "</td><td>" +
          esc(c.capacite) +
          "</td></tr>"
      )
      .join("");

    return (
      "<h2>Rapport CFP</h2>" +
      "<p>Type: " +
      esc(options.type) +
      "</p>" +
      "<table border='1' cellpadding='6' cellspacing='0'>" +
      "<thead><tr><th>Nom</th><th>Type</th><th>Sous-division</th><th>Capacite</th></tr></thead>" +
      "<tbody>" +
      rows +
      "</tbody></table>"
    );
  }

  window.AppData = {
    getCentres,
    getCentre,
    addCentre,
    updateCentre,
    deleteCentre,
    getUsers,
    addUser,
    updateUser,
    disableUser,
    deleteUser,
    getSettings,
    addSetting,
    deleteSetting,
    getYear,
    setYear,
    incrementCycle,
    getDashboardData,
    getStatsData,
    getLogs,
    generateReportHtml
  };
})();

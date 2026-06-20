(function () {
    "use strict";

    function initTabs() {
        var bar = document.querySelector("[data-tabs]");
        if (!bar) return;
        var tabs = Array.prototype.slice.call(document.querySelectorAll("[data-tab]"));
        var panels = Array.prototype.slice.call(document.querySelectorAll("[data-panel]"));

        function activate(name) {
            var matched = false;
            panels.forEach(function (panel) {
                var on = panel.getAttribute("data-panel") === name;
                panel.classList.toggle("active", on);
                if (on) matched = true;
            });
            if (!matched) return false;
            tabs.forEach(function (tab) {
                if (!tab.classList.contains("tab")) return;
                var on = tab.getAttribute("data-tab") === name;
                tab.classList.toggle("active", on);
                tab.setAttribute("aria-selected", on ? "true" : "false");
            });
            return true;
        }

        function fromHash() {
            return (window.location.hash || "").replace(/^#/, "");
        }

        var first = bar.querySelector(".tab");
        if (!activate(fromHash()) && first) {
            activate(first.getAttribute("data-tab"));
        }

        document.addEventListener("click", function (event) {
            var link = event.target.closest("[data-tab]");
            if (!link) return;
            var name = link.getAttribute("data-tab");
            if (activate(name)) {
                event.preventDefault();
                if (window.history.replaceState) {
                    window.history.replaceState(null, "", "#" + name);
                } else {
                    window.location.hash = name;
                }
            }
        });

        window.addEventListener("hashchange", function () {
            var name = fromHash();
            if (name) activate(name);
        });
    }

    function initRefresh() {
        var seconds = parseInt(document.body.getAttribute("data-refresh") || "0", 10);
        if (!seconds) return;
        window.setInterval(function () {
            if (document.hidden) return;
            fetch(window.location.pathname + window.location.search, {
                headers: { "X-Requested-With": "fetch" },
                cache: "no-store"
            })
                .then(function (resp) {
                    if (!resp.ok) throw new Error("refresh failed");
                    return resp.text();
                })
                .then(function (html) {
                    var doc = new DOMParser().parseFromString(html, "text/html");
                    var fresh = doc.getElementById("content");
                    var current = document.getElementById("content");
                    if (fresh && current) {
                        current.innerHTML = fresh.innerHTML;
                        initTabs();
                    }
                })
                .catch(function () {
                    /* leave the stale view in place and retry on the next tick */
                });
        }, seconds * 1000);
    }

    function start() {
        initTabs();
        initRefresh();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start);
    } else {
        start();
    }
})();

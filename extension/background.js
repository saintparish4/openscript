// The toolbar button opens the side panel, and that is all this worker does.
// The interpreter lives in the panel page, which stays alive for as long as
// the panel is open; a service worker is stopped whenever it idles, and would
// pay the boot again on every wake.
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

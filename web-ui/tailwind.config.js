/** @type {import('tailwindcss').Config} */
// Tailwind v3 (pinned in Trunk.toml under [tools]). Trunk runs the standalone
// CLI at `trunk build` time, so the UI no longer depends on the Play CDN.
module.exports = {
  content: ["./index.html", "./src/**/*.rs"],
  theme: {
    extend: {},
  },
  plugins: [],
};

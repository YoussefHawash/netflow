/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Dark UI palette consumed by every component via class names like
        // "bg-app-surface", "text-app-muted", "border-app-line/30", ...
        app: {
          bg: "#0d1117",
          surface: "#161b22",
          raised: "#1c222a",
          line: "#21262d",
          border: "#30363d",
          text: "#e6edf3",
          muted: "#9ca3af",
          subtle: "#6b7280",
          blue: "#58a6ff",
          blueStrong: "#1f6feb",
          cyan: "#56d4dd",
          green: "#3fb950",
          orange: "#f0883e",
          orangeDark: "#cc6929",
          violet: "#a371f7",
          yellow: "#d29922",
          danger: "#f85149",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica",
          "Arial",
          "sans-serif",
        ],
      },
    },
  },
  plugins: [],
};

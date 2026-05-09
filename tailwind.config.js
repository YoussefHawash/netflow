export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        app: {
          bg: "#111318",
          shell: "#151820",
          surface: "#191d26",
          raised: "#202530",
          line: "#2a303b",
          border: "#384150",
          text: "#f2f4f8",
          muted: "#a6afbf",
          subtle: "#737d8f",
          blue: "#9ab5ff",
          green: "#8ac7a0",
          orange: "#d6a15f",
          danger: "#e18484",
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

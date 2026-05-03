export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"]
      },
      colors: {
        ink: "#070b10",
        panel: "#101820",
        line: "#253342",
        cyber: "#20d6b3",
        alert: "#f59e0b",
        breach: "#fb7185"
      }
    }
  },
  plugins: []
};


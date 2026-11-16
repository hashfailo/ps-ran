/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#07111f",
        panel: "#0d1a2b",
        line: "#1d3148",
        cyan: "#38bdf8",
        signal: "#a3e635",
        danger: "#fb7185",
        amber: "#fbbf24"
      }
    }
  },
  plugins: []
};

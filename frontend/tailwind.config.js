/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/**/*.{js,jsx,ts,tsx}', // This tells Tailwind to look for class usage in all files under the src directory
    './public/index.html', // Optional: Include if you are using Tailwind classes in your HTML file
  ],
  theme: {
    extend: {
      colors: {
        primary: '#1D4ED8', // Example custom color
        secondary: '#9333EA', // Example custom color
      },
      // You can extend other properties like spacing, fonts, etc., here if needed
    },
  },
  plugins: [],
};

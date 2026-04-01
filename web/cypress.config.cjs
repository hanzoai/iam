const { defineConfig } = require("cypress");

module.exports = defineConfig({
  e2e: {
    baseUrl: "http://localhost:8000",
    "retries": {
      "runMode": 2,
      "openMode": 0
    }
  },
});

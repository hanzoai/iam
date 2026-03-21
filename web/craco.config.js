const path = require("path");

module.exports = {
  devServer: {
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/swagger": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/files": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/.well-known/openid-configuration": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/cas/**/serviceValidate": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/cas/**/proxyValidate": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/cas/**/proxy": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/cas/**/validate": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/cas/**/p3/serviceValidate": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/cas/**/p3/proxyValidate": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/scim": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  style: {
    postcss: {
      mode: "file",
    },
  },
  webpack: {
    configure: (webpackConfig, { env, paths }) => {
      paths.appBuild = path.resolve(__dirname, "build-temp");
      webpackConfig.output.path = path.resolve(__dirname, "build-temp");

      // ignore webpack warnings by source-map-loader
      webpackConfig.ignoreWarnings = [
        function ignoreSourcemapsloaderWarnings(warning) {
          return (
            warning.module &&
            warning.module.resource.includes("node_modules") &&
            warning.details &&
            warning.details.includes("source-map-loader")
          );
        },
      ];

      // use polyfill Buffer with Webpack 5
      webpackConfig.resolve.fallback = {
        buffer: require.resolve("buffer/"),
        process: false,
        util: false,
        url: false,
        zlib: false,
        stream: false,
        http: false,
        https: false,
        assert: false,
        crypto: false,
        os: false,
        fs: false,
      };

      return webpackConfig;
    },
  },
};

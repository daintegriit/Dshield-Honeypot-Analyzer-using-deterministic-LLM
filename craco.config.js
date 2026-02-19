// craco.config.js
const path = require('path');

module.exports = {
  webpack: {
    configure: (webpackConfig) => {
      webpackConfig.module.rules.push({
        test: /\.(glb|gltf)$/,
        use: [
          {
            loader: 'file-loader',
            options: {
              name: '[name].[ext]',
              outputPath: 'assets/models',
            },
          },
        ],
      });

      // Add Cesium alias and configuration
      webpackConfig.resolve.alias = {
        ...webpackConfig.resolve.alias,
        cesium: path.resolve(__dirname, 'node_modules/cesium/Source'),
      };

      webpackConfig.output.sourcePrefix = '';

      webpackConfig.amd = {
        toUrlUndefined: true,
      };

      return webpackConfig;
    },
  },
};

const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
  mode: 'production',
  entry: {
    background: './background.js',
    popup: './popup/popup.js',
    content: './content.js'
  },output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', {
                modules: 'commonjs',   // Преобразует import → require
                targets: { chrome: '100' }
              }]
            ]
          }
        }
      },
      {
        test: /\.wasm$/,
        type: 'webassembly/async',
      }
    ]
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: "manifest.json", to: "." },
        { from: "warning-banner.html", to: "." },
        { from: "popup/popup.html", to: "./popup/" },
        { from: "popup/popup.js", to: "./popup/" },
        { from: "popup/popup.css", to: "./popup/" },
        { from: "mlp_model.onnx", to: "." },
        { from: "scaler_params.json", to: "." },
        { from: "whitelist.json", to: "." },
        { from: "128.png", to: "." },
        { from: "icons/*", to: "." },
        { from: "content.js", to: "." },
        // Копируем WASM из node_modules
        { from: "node_modules/onnxruntime-web/dist/*.wasm", to: "." }
      ],
    }),
  ],
  experiments: {
    asyncWebAssembly: true
  }
};
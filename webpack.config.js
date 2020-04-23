/*
* @Author: amitshah
* @Date:   2020-03-27 14:27:20
* @Last Modified by:   amitshah
* @Last Modified time: 2020-03-27 14:34:51
*/
const path = require('path');

module.exports = {
  entry: './src/client.js',
  output: {
    filename: 'main.js',
    path: path.resolve(__dirname, 'dist'),
  },
};
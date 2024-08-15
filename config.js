const consts = require('./consts')(),
      app = {
        port: 3000,
        host: '0.0.0.0',
        auth_method: consts.METHODS.NO_AUTH
      }

module.exports = () => {
  return app
}

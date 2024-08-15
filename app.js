const net = require("net"),
  server = new net.createServer(),
  config = require("./config")(server),
  Proxy = require("./proxy")(server);

server
  .listen(config.port, config.host)
  .on("listening", () => {
    console.log(`simple-proxy server listening on ${config.port}`);
  })
  .on("close", () => {
    console.log("simple-proxy server closed");
  })
  .on("error", (err) => {
    console.error("simple-proxy server throw error", err);
  })
  .on("connection", (socket) => {
    var proxy = Proxy(socket);
    // data package come in
    socket
      .on("data", (buf) => {
        proxy.handle(buf);
      })
      .on("end", () => {
        console.log(`socket ${proxy._session.id} end`);
      })
      .on("close", (hadError) => {
        console.log(
          `socket ${proxy._session.id} closed with error: ${hadError}`
        );
      })
      .on("error", (err) => {
        console.error(`socket ${proxy._session.id} throw error`, err);
      })
      .on("timeout", () => {
        console.log(`socket ${proxy._session.id} timeout`);
      });
  });

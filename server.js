const WebSocket = require("ws");
const net = require("net");
const server = new WebSocket.Server({ port: 9000 });

console.log("start websocket server");
// 当有客户端连接时触发
server.on("connection", (socket) => {
  let tcpSocket = null;
  // 处理收到的消息
  socket.on("message", (data) => {
    const parseData = JSON.parse(data);
    switch (parseData.type) {
      case "data":
        const buffer = Buffer.from(parseData.data, "base64");
        tcpSocket.write(buffer, () => {});
        // 发送数据
        break;
      case "prepare":
        // 建立一个tcp连接
        if (!tcpSocket) {
          // 解析dns
          tcpSocket = net.createConnection({
            port: parseData.data.port,
            host: parseData.data.host,
          });
          // }
          tcpSocket
            .on("connect", (data) => {
              if (!parseData.data.tls) {
                socket.send(
                  JSON.stringify({
                    type: "prepareComplete",
                    data: {
                      ip: tcpSocket.localAddress,
                      port: tcpSocket.localPort,
                    },
                  })
                );
              }
            })
            .on("secureConnect", (data) => {
              socket.send(JSON.stringify({ type: "prepareComplete" }));
            })
            .on("data", (data) => {
              socket.send(
                JSON.stringify({
                  type: "response",
                  data: data.toString("base64"),
                })
              );
            })
            .on("error", (error) => {
              console.log("异常错误:", error);
            })
            .on("end", (data) => {
              socket.send(JSON.stringify({ type: "end" }));
              tcpSocket.end();
            });
        }

        break;
      default:
    }
    // 在此处添加处理消息的逻辑
  });

  // 处理连接关闭
  socket.on("close", () => {
    console.log("Client disconnected");
  });
});

const net = require("net"),
  dns = require("node:dns"),
  WebSocket = require("ws"),
  { assert } = require("console"),
  uuid = require("uuid"),
  utils = require("./utils"),
  consts = require("./consts")(),
  config = require("./config")();

function Proxy(socket) {
  return {
    /**
     * proxy socket
     */
    _socket: socket,

    /**
     * session
     */
    _session: {
      id: uuid.v1(),
      buffer: Buffer.alloc(0),
      offset: 0,
      state: consts.STATE.METHOD_NEGOTIATION,
    },

    /**
     * The client connects to the server, and sends a version identifier/method selection message:
     * +----+----------+----------+
     * |VER | NMETHODS | METHODS  |
     * +----+----------+----------+
     * | 1  |    1     | 1 to 255 |
     * +----+----------+----------+
     */
    parseMethods() {
      let buf = this._session.buffer;
      let offset = this._session.offset;

      var checkNull = (offset) => {
        return typeof buf[offset] === undefined;
      };

      if (checkNull(offset)) {
        return false;
      }
      let socksVersion = buf[offset++];
      assert(
        socksVersion == consts.SOCKS_VERSION,
        `socket ${this._session.id} only support socks version 5, got [${socksVersion}]`
      );
      if (socksVersion != consts.SOCKS_VERSION) {
        this._socket.end();
        return false;
      }

      if (checkNull(offset)) {
        return false;
      }
      let methodLen = buf[offset++];
      assert(
        methodLen >= 1 && methodLen <= 255,
        `socket ${this._session.id} methodLen's value [${methodLen}] is invalid`
      );

      if (checkNull(offset + methodLen - 1)) {
        return false;
      }
      let methods = [];
      for (let i = 0; i < methodLen; i++) {
        let method = consts.METHODS.get(buf[offset++]);
        if (!!method) {
          methods.push(method);
        }
      }

      this._session.offset = offset;

      return methods;
    },

    /** socks server select auth method */
    selectMethod(methods) {
      let method = consts.METHODS.NO_ACCEPTABLE;
      for (let i = 0; i < methods.length; i++) {
        if (methods[i] == config.auth_method) {
          method = config.auth_method;
        }
      }
      this._session.method = method;

      return method;
    },

    /**
     * The server selects from one of the methods given in METHODS, and sends a METHOD selection message
     * +----+--------+
     * |VER | METHOD |
     * +----+--------+
     * | 1  |   1    |
     * +----+--------+
     * @param {*} method auth method selected
     */
    replyMethod(method) {
      this._socket.write(Buffer.from([consts.SOCKS_VERSION, method[0]]));
    },

    /**
     * This begins with the client producing a Username/Password request:
     * +----+------+----------+------+----------+
     * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     * +----+------+----------+------+----------+
     * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     * +----+------+----------+------+----------+
     */
    parseUsernamePasswd() {
      let buf = this._session.buffer;
      let offset = this._session.offset;

      var req = {};

      var checkNull = (offset) => {
        return typeof buf[offset] === undefined;
      };

      if (checkNull(offset)) {
        return false;
      }
      let authVersion = buf[offset++];
      assert(
        authVersion == consts.USERNAME_PASSWD_AUTH_VERSION,
        `socket ${this._session.id} only support auth version ${consts.USERNAME_PASSWD_AUTH_VERSION}, got [${authVersion}]`
      );
      if (authVersion != consts.USERNAME_PASSWD_AUTH_VERSION) {
        this._socket.end();
        return false;
      }

      if (checkNull(offset)) {
        return false;
      }
      let uLen = buf[offset++];
      assert(
        uLen >= 1 && uLen <= 255,
        `socket ${this._session.id} got wrong ULEN [${uLen}]`
      );
      if (uLen >= 1 && uLen <= 255) {
        if (checkNull(offset + uLen - 1)) {
          return false;
        }
        req.username = buf.slice(offset, offset + uLen).toString("utf8");
        offset += uLen;
      } else {
        this._socket.end();
        return false;
      }

      if (checkNull(offset)) {
        return false;
      }
      let pLen = buf[offset++];
      assert(
        pLen >= 1 && pLen <= 255,
        `socket ${this._session.id} got wrong PLEN [${pLen}]`
      );
      if (pLen >= 1 && pLen <= 255) {
        if (checkNull(offset + pLen - 1)) {
          return false;
        }
        req.passwd = buf.slice(offset, offset + pLen).toString("utf8");
        offset += pLen;
      } else {
        this._socket.end();
        return false;
      }

      this._session.offset = offset;

      return req;
    },

    /**
     * The server verifies the supplied UNAME and PASSWD, and sends the following response:
     *  +----+--------+
     *  |VER | STATUS |
     *  +----+--------+
     *  | 1  |   1    |
     *  +----+--------+
     */
    replyAuth(succeeded) {
      let reply = [
        consts.USERNAME_PASSWD_AUTH_VERSION,
        succeeded ? consts.AUTH_STATUS.SUCCESS : consts.AUTH_STATUS.FAILURE,
      ];
      if (succeeded) {
        this._socket.write(Buffer.from(reply));
      } else {
        this._socket.end(Buffer.from(reply));
      }
    },

    /**
     * The SOCKS request is formed as follows:
     * +----+-----+-------+------+----------+----------+
     * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
     * +----+-----+-------+------+----------+----------+
     * | 1  |  1  | X'00' |  1   | Variable |    2     |
     * +----+-----+-------+------+----------+----------+
     */
    parseRequests() {
      let buf = this._session.buffer;
      let offset = this._session.offset;

      let req = {};

      var checkNull = (offset) => {
        return typeof buf[offset] === undefined;
      };

      if (checkNull(offset)) {
        return false;
      }
      let socksVersion = buf[offset++];
      assert(
        socksVersion == consts.SOCKS_VERSION,
        `socket ${this._session.id} only support socks version 5, got [${socksVersion}]`
      );
      if (socksVersion != consts.SOCKS_VERSION) {
        this._socket.end();
        return false;
      }

      if (checkNull(offset)) {
        return false;
      }
      req.cmd = consts.REQUEST_CMD.get(buf[offset++]);
      if (!req.cmd || req.cmd != consts.REQUEST_CMD.CONNECT) {
        // 不支持的 cmd || 暂时只支持 connect
        this._socket.end();
        return false;
      }

      if (checkNull(offset)) {
        return false;
      }
      req.rsv = buf[offset++];
      assert(
        req.rsv == consts.RSV,
        `socket ${this._session.id} rsv should be ${consts.RSV}`
      );

      if (checkNull(offset)) {
        return false;
      }
      req.atyp = consts.ATYP.get(buf[offset++]);
      if (!req.atyp) {
        // 不支持的 atyp
        this._socket.end();
        return false;
      } else if (req.atyp == consts.ATYP.IPV4) {
        let ipLen = 4;
        if (checkNull(offset + ipLen - 1)) {
          return false;
        }
        req.ip = `${buf[offset++]}.${buf[offset++]}.${buf[offset++]}.${
          buf[offset++]
        }`;
      } else if (req.atyp == consts.ATYP.FQDN) {
        if (checkNull(offset)) {
          return false;
        }
        let domainLen = buf[offset++];
        if (checkNull(offset + domainLen - 1)) {
          return false;
        }
        req.domain = buf.slice(offset, offset + domainLen).toString("utf8");
        offset += domainLen;
      } else {
        // 其他暂时不支持
        this._socket.end();
        return false;
      }

      let portLen = 2;
      if (checkNull(offset + portLen - 1)) {
        return false;
      }
      req.port = buf.readUInt16BE(offset);
      offset += portLen;

      this._session.offset = offset;

      return req;
    },

    /**
     * The server evaluates the request, and returns a reply formed as follows:
     * +----+-----+-------+------+----------+----------+
     * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
     * +----+-----+-------+------+----------+----------+
     * | 1  |  1  | X'00' |  1   | Variable |    2     |
     * +----+-----+-------+------+----------+----------+
     * @param {*} req client requests
     */
    dstConnect(req) {
      let dstHost = req.domain || req.ip;
      // 下面可能不会走
      // if (err || !ip) {
      // failure reply
      if (false) {
        let reply = [
          consts.SOCKS_VERSION,
          consts.REP.HOST_UNREACHABLE[0],
          consts.RSV,
          consts.ATYP.IPV4[0],
        ]
          .concat(utils.ipbytes("127.0.0.1")) // ip: 127.0.0.1
          .concat([0x00, 0x00]); // port: 0x0000
        // close connection
        this._socket.end(Buffer.from(reply));
      } else {
        // 创建websocket
        const proxyWebSocket = new WebSocket(
        // 替换成服务端地址
        );
        proxyWebSocket.on("open", () => {
          // 向服务端发送prepare连接信息
          proxyWebSocket.send(
            JSON.stringify({
              type: "prepare",
              data: {
                port: req.port,
                host: dstHost,
              },
            })
          );
        });

        proxyWebSocket.on("message", (data) => {
          const parseData = JSON.parse(data);
          if (parseData.type === "response") {
          }
          switch (parseData.type) {
            case "prepareComplete":
              let bytes = [
                consts.SOCKS_VERSION,
                consts.REP.SUCCEEDED[0],
                consts.RSV,
                consts.ATYP.IPV4[0],
              ]
                // dstSocket.localAddress or default 127.0.0.1
                .concat(utils.ipbytes(parseData.data.ip || "127.0.0.1"))
                // default port 0x00
                .concat([0x00, 0x00]);

              let reply = Buffer.from(bytes);
              // use dstSocket.localPort override default port 0x0000
              reply.writeUInt16BE(parseData.data.port, reply.length - 2);
              this._socket.write(reply);
              break;
            case "response":
              let buffer = Buffer.from(parseData.data, "base64");
              this._socket.write(buffer);
              break;
            case "end":
              this._socket.end();
              break;
            default:
              console.log("哈？");
          }
        });
        proxyWebSocket.on("error", (error) => {
          console.log(error);
        });
        this._session.proxyWebSocket = proxyWebSocket;
      }
    },

    /**
     * called by socket's 'data' event listener
     * @param {Buffer} buf data buffer
     */
    handle(buf) {
      // before proxy forward phase, otherwise do nothing
      if (this._session.state <= consts.STATE.PROXY_FORWARD) {
        // append data to session.buffer
        this._session.buffer = Buffer.concat([this._session.buffer, buf]);

        // discard processed bytes and move on to the next phase
        const discardProcessedBytes = (nextState) => {
          this._session.buffer = this._session.buffer.slice(
            this._session.offset
          );
          this._session.offset = 0;
          this._session.state = nextState;
        };

        switch (this._session.state) {
          case consts.STATE.METHOD_NEGOTIATION:
            let methods = this.parseMethods();
            if (!!methods) {
              // read complete data
              let method = this.selectMethod(methods);
              this.replyMethod(method);
              switch (method) {
                case consts.METHODS.USERNAME_PASSWD:
                  discardProcessedBytes(consts.STATE.AUTHENTICATION);
                  break;
                case consts.METHODS.NO_AUTH:
                  discardProcessedBytes(consts.STATE.REQUEST_CONNECT);
                  break;
                case consts.METHODS.NO_ACCEPTABLE:
                  this._socket.end();
                  break;
                default:
                  this._socket.end();
              }
            }
            break;
          // curl www.baidu.com --socks5 127.0.0.1:3000 --socks5-basic --proxy-user  oiuytre:yhntgbrfvedc
          case consts.STATE.AUTHENTICATION:
            // add gssapi support
            // need check this._session.method for parse data
            let userinfo = this.parseUsernamePasswd();
            if (!!userinfo) {
              // read complete data
              let succeeded =
                userinfo.username === config.username &&
                userinfo.passwd === config.passwd;
              discardProcessedBytes(
                succeeded
                  ? consts.STATE.REQUEST_CONNECT
                  : consts.STATE.AUTHENTICATION
              );
              this.replyAuth(succeeded);
            }
            break;
          case consts.STATE.REQUEST_CONNECT:
            let req = this.parseRequests();
            if (!!req) {
              // read complete data
              this.dstConnect(req);
              discardProcessedBytes(consts.STATE.PROXY_FORWARD);
            }
            break;
          case consts.STATE.PROXY_FORWARD:
            this._session.proxyWebSocket.send(
              JSON.stringify({
                type: "data",
                data: buf.toString("base64"),
              })
            );
            discardProcessedBytes(consts.STATE.PROXY_FORWARD);
            break;
          default:
            console.log(`handle state [${this._session.state}]`, this._session);
        }
      }
    },
  };
}

module.exports = (server) => {
  return Proxy;
};

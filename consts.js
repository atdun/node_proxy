/** socks 5 */
const SOCKS_VERSION = 0x05,

      STATE = {
        METHOD_NEGOTIATION: 0x00,
        AUTHENTICATION: 0x01,
        REQUEST_CONNECT: 0x02,
        PROXY_FORWARD: 0x03
      },

      /**
       * o  X'00' NO AUTHENTICATION REQUIRED
       * o  X'01' GSSAPI
       * o  X'02' USERNAME/PASSWORD
       * o  X'03' to X'7F' IANA ASSIGNED
       * o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
       * o  X'FF' NO ACCEPTABLE METHODS
       */
      METHODS = {
        NO_AUTH: [0x00, 'no_auth'],
        GSSAPI: [0x01, 'gssapi'],
        USERNAME_PASSWD: [0x02, 'username_password'],
        NO_ACCEPTABLE: [0xFF, 'no_acceptable_methods'],

        get(method) {
          switch(method) {
            case this.NO_AUTH[0]:
              return this.NO_AUTH
            case this.GSSAPI[0]:
              return this.GSSAPI
            case this.USERNAME_PASSWD[0]:
              return this.USERNAME_PASSWD
          }
          console.error(`method [${method}] is not supported`)
          return false
        }
      },

      /**
       * o  CONNECT X'01'
       * o  BIND X'02'
       * o  UDP ASSOCIATE X'03'
       */
      REQUEST_CMD = {
        CONNECT: [0x01, 'connect'],
        BIND: [0x02, 'bind'],
        UDP_ASSOCIATE: [0x03, 'udp_associate'],

        get(cmd) {
          switch(cmd) {
            case this.CONNECT[0]:
              return this.CONNECT
            case this.BIND[0]:
              return this.BIND
            case this.UDP_ASSOCIATE[0]:
              return this.UDP_ASSOCIATE
          }
          console.error(`cmd [${cmd}] is not supported`)
          return false
        }
      },

      /** reserved byte value */
      RSV = 0x00,

      /**
       * o  IP V4 address: X'01'
       * o  DOMAINNAME: X'03'
       * o  IP V6 address: X'04'
       */
      ATYP = {
        IPV4: [0x01, 'ipv4'],
        FQDN: [0x03, 'domain name'],
        IPV6: [0x04, 'ipv6'],

        get(atyp) {
          switch(atyp) {
            case this.IPV4[0]:
              return this.IPV4
            case this.FQDN[0]:
              return this.FQDN
            case this.IPV6[0]:
              return this.IPV6
          }
          console.error(`atpy [${atyp}] is not supported`)
          return false
        }
      },

      /**
       * o  X'00' succeeded
       * o  X'01' general SOCKS server failure
       * o  X'02' connection not allowed by ruleset
       * o  X'03' Network unreachable
       * o  X'04' Host unreachable
       * o  X'05' Connection refused
       * o  X'06' TTL expired
       * o  X'07' Command not supported
       * o  X'08' Address type not supported
       * o  X'09' to X'FF' unassigned
       */
      REP = {
        SUCCEEDED: [0x00, 'succeeded'],
        GENERAL_FAILURE: [0x01, 'general SOCKS server failure'],
        NOT_ALLOWED: [0x02, 'connection not allowed by ruleset'],
        NETWORK_UNREACHABLE: [0x03, 'Network unreachable'],
        HOST_UNREACHABLE: [0x04, 'Host unreachable'],
        CONNECTION_REFUSED: [0x05, 'Connection refused'],
        TTL_EXPIRED: [0x06, 'TTL expired'],
        COMMAND_NOT_SUPPORTED: [0x07, 'Command not supported'],
        ADDRESS_TYPE_NOT_SUPPORTED: [0x08, 'Address type not supported']
      },

      /**
       * The VER field contains the current version of the subnegotiation, which is X'01'
       * username/password auth version
       */
      USERNAME_PASSWD_AUTH_VERSION = 0x01,

      /**
       * auth status
       */
      AUTH_STATUS = {
        SUCCESS: 0x00,
        FAILURE: 0X01
      }

module.exports = () => {

  return {
    SOCKS_VERSION: SOCKS_VERSION,
    STATE: STATE,
    METHODS: METHODS,
    REQUEST_CMD: REQUEST_CMD,
    RSV: RSV,
    ATYP: ATYP,
    REP: REP,
    USERNAME_PASSWD_AUTH_VERSION, USERNAME_PASSWD_AUTH_VERSION,
    AUTH_STATUS: AUTH_STATUS
  }

}
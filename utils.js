function ipbytes(ip) {
    return ip.split('.').map(octet => parseInt(octet, 10));
} 
module.exports = {ipbytes}
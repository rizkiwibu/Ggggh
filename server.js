const http = require("http");
const app = require("./index");
const PORT = process.env.PORT || 8080;

http.createServer(app).listen(PORT, () => {
    console.log(`
Anjay Berjalan Coy
Server Berjalan Di http://localhost:` + port)
console.log(`Woy ${creator}`)
})
const fs = require("fs");
const {signRavencoinTransaction} = require("./sign2");
const transactionData = JSON.parse(fs.readFileSync("./data.json", "utf8"));

const signedTransaction = signRavencoinTransaction(transactionData.debug);
console.log("Signed Transaction:", signedTransaction);

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const privateKey = fs.readFileSync("callback_private.pem");
const cosignerPubKey = fs.readFileSync("cosigner_public.pem");
const app = express();

app.use(
  express.urlencoded({
    extended: true,
  })
);
app.use(express.json());

app.use(function (req) {
  req.rawBody = "";
  req.setEncoding("utf8");
  req.on("data", function (chunk) {
    req.rawBody += chunk;
  });
  req.on("end", function () {
    req.next();
  });
});

app.post("/v2/tx_sign_request", async (req, res) => {
  let verified;
  try {
    const tx = jwt.decode(req.rawBody);
    console.log(tx);

    const { requestId } = tx;
    verified = jwt.verify(req.rawBody, cosignerPubKey);
    if (verified) {
      let action = "REJECT";
      let rejectionReason = "Logic returned false";
      const signedRes = jwt.sign(
        {
          action,
          requestId,
          rejectionReason,
        },
        privateKey,
        { algorithm: "RS256" }
      );
      res.send(signedRes);
    }
  } catch (e) {
    res.sendStatus(401);
  }
});
app.listen(3000);

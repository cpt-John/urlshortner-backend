const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const cryptoRandomString = require("crypto-random-string");
const mongodb = require("mongodb");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

const port = process.env.PORT || 3000;
dotenv.config();

const key = process.env.KEY;
const saltRounds = 6;
const tokenExpiery = { login: 10, mailVerification: 2, passwordReset: 2 };

app.use(bodyParser.json());
app.use(cors());

app.listen(port, () => {
  console.log("app listing in port " + port);
});

//mailing
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.C_EMAIL,
    pass: process.env.C_PASSWORD,
  },
});

async function verificationMail(toMail, link, data) {
  let mailOptions = {
    from: process.env.EMAIL,
    to: toMail,
    subject: "verification link",

    html: `<p>${data}</p></br>
    <a href=${link}>Click HERE</a>`,
  };
  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log("error is " + error);
        reject(error);
      } else {
        console.log("Email sent: " + info.response);
        resolve("mailed");
      }
    });
  });
}

//mongodb
const dbName = "UrlShortner";
const collName1 = "users";
const collName2 = "urls";
//mongodb://localhost:27017/?readPreference=primary&appname=MongoDB%20Compass%20Community&ssl=false
const uri = `mongodb+srv://${process.env.D_EMAIL}:${process.env.D_PASSWORD}@cluster0-lyx1k.mongodb.net/UrlShortner?retryWrites=true&w=majority`;
// const uri = `mongodb://localhost:27017/?readPreference=primary&ssl=false`;
const mongoClient = mongodb.MongoClient;

app.post("/login", async function (req, res) {
  if (!req.body["email"] || !req.body["password"]) {
    res.status(400).json({
      message: "email or password missing",
    });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  let result;
  try {
    result = await collection.findOne({ email: req.body["email"] });
    if (!result) {
      res.status(400).json({ message: "email is not registered" });
      return;
    } else if (result["verified"] !== true) {
      res.status(400).json({ message: "email is not verified" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
  } finally {
    client.close();
  }
  try {
    let pass = await bcrypt.compare(req.body["password"], result["password"]);
    if (!pass) {
      res.status(401).json({ message: "wrong password" });
    } else if (pass) {
      let token_expiry = tokenExpiery["login"];
      let token = jwt.sign({ email: req.body["email"], type: "login" }, key, {
        expiresIn: token_expiry + "m",
      });
      res.status(200).json({ message: "credentials verified!", token });
    }
  } catch {
    res.status(500).json({ message: "couldn't verify password" });
  }
});

app.post("/register", async function (req, res) {
  if (!req.body["email"] || !req.body["password"] || !req.body["name"]) {
    res.status(400).json({
      message: "email or password or name missing",
    });
    return;
  }
  try {
    let hash = await bcrypt.hash(req.body["password"], saltRounds);
    req.body["password"] = hash;
  } catch {
    res.status(400).json({
      message: "hashing failed",
    });
    return;
  }

  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  try {
    let result = await collection.findOne({ email: req.body["email"] });
    if (result) {
      res.status(400).json({ message: "email already exists" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }
  try {
    req.body["verified"] = false;
    req.body["dates"] = [];
    await collection.insertOne(req.body);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "filed to register" });
    return;
  } finally {
    client.close();
  }
  let token_expiry = tokenExpiery["mailVerification"];
  let token = jwt.sign(
    { email: req.body["email"], type: "mailVerification" },
    key,
    { expiresIn: token_expiry + "m" }
  );
  let link = process.env.APPLINK + "login/" + token;
  let text = `Follow link to verify email token is valid only for ${token_expiry} minute(s)`;
  let result = await verificationMail(req.body["email"], link, text).catch(
    (err) => {
      res.status(500).json({ message: "filed to send mail" });
    }
  );
  if (result) {
    res
      .status(200)
      .json({ message: "verification mail send to " + req.body["email"] });
  }
});

app.post("/verifyEmail", async function (req, res) {
  if (!req.body["jwt"]) {
    res.status(400).json({
      message: "token missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "invalid token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "mailVerification") {
    try {
      let result = await collection.updateOne(
        { email: data["email"] },
        { $set: { verified: true } }
      );
      if (!result) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        res
          .status(200)
          .json({ message: "your email has been verified you can login now" });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
  }
});

app.post("/resetPassLink", async function (req, res) {
  if (!req.body["email"]) {
    res.status(400).json({
      message: "email  missing",
    });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  try {
    let result = await collection.findOne({ email: req.body["email"] });
    if (!result) {
      res.status(400).json({ message: "email is not registered" });
      return;
    } else if (result["verified"] !== true) {
      res.status(400).json({ message: "email is not verified" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }

  let token_expiry = tokenExpiery["passwordReset"];
  let token = jwt.sign(
    { email: req.body["email"], type: "passwordReset" },
    key,
    { expiresIn: token_expiry + "m" }
  );
  let link = process.env.APPLINK + "resetpass/" + token;
  let text = `Follow link to reset password token is valid only for ${token_expiry} minute(s)`;
  let result = await verificationMail(req.body["email"], link, text).catch(
    (err) => {
      res.status(500).json({ message: "filed to send mail" });
    }
  );
  if (result) {
    res
      .status(200)
      .json({ message: "reset link send to " + req.body["email"] });
  }
});

app.post("/resetPass", async function (req, res) {
  if (!req.body["jwt"] || !req.body["password"]) {
    res.status(400).json({
      message: "token or password missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "invalid token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "passwordReset") {
    //new pass
    let hash;
    try {
      hash = await bcrypt.hash(req.body["password"], saltRounds);
    } catch {
      res.status(400).json({
        message: "hashing failed",
      });
      return;
    }
    //set new pass
    try {
      let result = await collection.updateOne(
        { email: data["email"] },
        { $set: { password: hash } }
      );
      if (!result) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        res.status(200).json({
          message: "your password has been reset",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
    client.close();
  }
});

app.post("/verifyLogin", async function (req, res) {
  if (!req.body["jwt"]) {
    res.status(400).json({
      message: "token missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "session ended login again" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "login") {
    try {
      let result = await collection.findOne({ email: data["email"] });
      if (!result) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        res.status(200).json({
          message: "login success!",
          result,
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
    client.close();
  }
});

//url methods
app.get("/SU/:url", async function (req, res) {
  let url = req.params["url"];
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  collection = client.db(dbName).collection(collName2);
  try {
    let result = await collection.findOne({ url_short: url });
    if (result) {
      res.writeHead(302, {
        Location: result["url_long"],
      });
      res.end();
    } else {
      res.status(404).end();
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }
  try {
    await collection.updateOne({ url_short: url }, { $inc: { count: 1 } });
  } catch (err) {
    return;
  } finally {
    client.close();
  }
});

app.post("/setUrl", async function (req, res) {
  if (!req.body["jwt"] || !req.body["name"] || !req.body["url"]) {
    res.status(400).json({
      message: "jwt or name or url missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "session ended login again" });
    return;
  }
  if (data["type"] != "login") {
    res.status(401).json({ message: "wrong token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  let collection = client.db(dbName).collection(collName1);
  try {
    let result = await collection.findOne({ email: data["email"] });
    if (!result) {
      res.status(400).json({ message: "email doesn't exists" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }
  collection = client.db(dbName).collection(collName2);
  try {
    let result = await collection.findOne({ url_long: req.body["url"] });
    if (result) {
      res.status(200).json({ message: "url already exists" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }
  let url_short = cryptoRandomString({ length: 7, type: "url-safe" });
  try {
    let new_doc = {
      user: data["email"],
      url_long: req.body["url"],
      url_short,
      count: 0,
      name: req.body["name"],
    };
    let result = await collection.insertOne(new_doc);
    if (result) res.status(200).json({ message: "added new url" });
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }
  collection = client.db(dbName).collection(collName1);
  let date = new Date().toDateString();
  try {
    let result = await collection.findOne({
      email: data["email"],
      "dates.date": date,
    });
    if (result) {
      try {
        await collection.updateOne(
          { email: data["email"], "dates.date": date },
          { $inc: { "dates.$.count": 1 } }
        );
      } catch (err) {
        console.log(err);
        return;
      } finally {
        client.close();
      }
    } else {
      let newDate = { date, count: 1 };
      try {
        await collection.updateOne(
          { email: data["email"] },
          { $push: { dates: newDate } }
        );
      } catch (err) {
        console.log(err);
        return;
      } finally {
        client.close();
      }
    }
  } catch (err) {
    console.log(err);
    client.close();
  }
});

app.post("/getUrls", async function (req, res) {
  if (!req.body["jwt"]) {
    res.status(400).json({
      message: "jwt or name or url missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "session ended login again" });
    return;
  }
  if (data["type"] != "login") {
    res.status(401).json({ message: "wrong token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  collection = client.db(dbName).collection(collName2);
  try {
    let result = await collection.find({ user: data["email"] }).toArray();
    result = result.map((obj) => {
      obj["url_short_val"] = obj["url_short"];
      obj["url_short"] = process.env.SERVERLINK + "SU/" + obj["url_short_val"];
      return obj;
    });
    res.status(200).json({ message: "retrieved", data: result });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "filed to retreive" });
    return;
  } finally {
    client.close();
  }
});

app.post("/deleteUrl", async function (req, res) {
  if (!req.body["jwt"] || !req.body["url_short"]) {
    res.status(400).json({
      message: "jwt or name or url missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "session ended login again" });
    return;
  }
  if (data["type"] != "login") {
    res.status(401).json({ message: "wrong token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  collection = client.db(dbName).collection(collName2);
  try {
    let result = await collection.deleteOne({
      url_short: req.body["url_short"],
    });
    res.status(200).json({ message: "deleted" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "filed to retreive" });
    return;
  } finally {
    client.close();
  }
});

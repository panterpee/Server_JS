const cors = require("cors");
const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken"); //keep user identity
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt"); //hash function

const app = express();
app.use(express.json());
app.use(
  cors({
    credentials: true,
    origin: ["http://localhost:8888"],
  })
);
app.use(cookieParser());

const port = 8000;
const secret = "serviceSecretData";

let conn = null;

// function init connection mysql
const initMySQL = async () => {
  conn = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "serviceData",
  });
};

app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const passwordHash = await bcrypt.hash(password, 10); //10 is example salt-password
    const officerData = {
      username: username,
      password: passwordHash,
    };
    const [results] = await conn.query(
      "INSERT INTO officer SET ?",
      officerData
    );
    res.json({
      message: "insert OK",
      results,
    });
  } catch (error) {
    console.log("error");
    res.json({
      message: "insert error",
      error,
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const [results] = await conn.query(
      "SELECT * FROM officer where username = ?",
      [username]
    );
    const officerData = results[0];
    const match = await bcrypt.compare(password, officerData.password);

     if (!match) {
      res.status(400).json({
        message: "wrong password",
        username
      });
      return false; //break function
    }
    
    //create token jwt token
    const token = jwt.sign({ username, role: "admin" }, secret, {
      expiresIn: "1h",
    });
    //-----cookie parser-1----
    res.cookie('token', token, {
      maxAge: 300000, //300ms 5min in browser
      secure: true,
      httpOnly: true,
      sameSite: "none",
    });
    
    res.json({
      username ,
      message: "login success",
      token,

    });
  } catch (error) {
    console.log("error", error);
    res.status(401).json({
      message: "login fail",
      error,
    });
  }
});


app.post("/api/login/data", async (req, res) => {
  try {
    const { officerName, product, part, malfunction, custumerPhone } = req.body;
    const dataResult = {
      officerName : officerName,
      product : product,
      part : part,
      malfunction : malfunction,
      custumerPhone : custumerPhone,
    }
    const [results] = await conn.query(
      "INSERT INTO dataService SET ?",
       dataResult
    );

    res.json({
      message: "insert data success",
      results
    });
  } catch (error) {
    console.log("error", error);
    res.json({
      message: "insert data fail",
      error,
    });
  }
});


app.get("/api/allData", async (req, res) => {
  //token check
  try {
    const authToken = req.cookies.token;
    if (!authToken) {
      throw { message: "No token found" };
    }
    console.log("authToken", authToken);
  
    const officer = jwt.verify(authToken, secret);
    console.log(officer)

    // recheck in db 
    const [checkResults] = await conn.query(
      "SELECT * FROM officer WHERE username = ?",
       officer.username
    );
    if (!checkResults[0]) {
      throw { message: "officer not found" };
    }
    console.log("officer", officer);
    // ----------------------------------------------
    const [results] = await conn.query("SELECT * FROM dataService");
    res.json({
      allData: results,
    });
  } catch (error) {
    console.log("error", error);
    res.json({
      message: "Authentication fail",
      error,
    });
  }
});

// Listen
app.listen(port, async () => {
  await initMySQL();
  console.log("Server started at port 8000");
});

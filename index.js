const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");
const passport = require("passport");
const session = require("express-session");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const OAuth2Strategy = require("passport-google-oauth2").Strategy;
const Razorpay = require("razorpay");
const crypto = require("crypto");
require('dotenv').config();

const app = express();
const port = 3005;

app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(express.json());

app.use(
  session({
    secret: "15672983lksdnvkdsvljsdvssd",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

const db = mysql.createConnection({
  host: "103.145.50.161",
  user: "development_Avinash",
  password: "@Inventory1",
  database: "development_Retail",
}); 

const jwtSecretKey = "yatayatismdnvlsvnvlefmv";

const clientid =
  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const clientsecret = "xxxxxxxxxxxxxxxxxxxxxxxxxx";


passport.use(
  new OAuth2Strategy(
    {
      clientID: clientid,
      clientSecret: clientsecret,
      callbackURL: "/auth/google/callback",
      scope: ["profile", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        db.query(
          "SELECT * FROM googlepass WHERE googleId = ?",
          [profile.id],
          async (error, results) => {
            if (error) {
              return done(error, null);
            }
            let user;
            if (results.length === 0) {
              db.query(
                "INSERT INTO googlepass (googleId, displayName, email, image) VALUES (?, ?, ?, ?)",
                [
                  profile.id,
                  profile.displayName,
                  profile.emails[0].value,
                  profile.photos[0].value,
                ],
                async (error, results) => {
                  if (error) {
                    return done(error, null);
                  }
                  db.query(
                    "SELECT * FROM googlepass WHERE id = ?",
                    [results.insertId],
                    (error, results) => {
                      if (error) {
                        return done(error, null);
                      }
                      user = results[0];
                      return done(null, user);
                    }
                  );
                }
              );
            } else {
              user = results[0];
              return done(null, user);
            }
          }
        );
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// initial google ouath login
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "http://localhost:3000/home",
    failureRedirect: "http://localhost:3000/",
  })
);

app.get("/login/sucess", async (req, res) => {
  if (req.user) {
    res.status(200).json({ message: "user Login", user: req.user });
  } else {
    res.status(400).json({ message: "Not Authorized" });
  }
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("http://localhost:3000");
  });
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000);
}
function sendOTP(email, otp) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "xxxxxxxxx@gmail.com",
      pass: "xxxxxxxxxxx",
    },
  });

  const mailOptions = {
    from: "your_email",
    to: email,
    subject: "OTP for Login",
    text: `Your OTP for login is: ${otp}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}


app.post("/logined", (req, res) => {
  const { email } = req.body;
  db.query(
    "SELECT * FROM rolebased WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        res.status(500).json({ error: "Internal Server Error" });
      } else if (results.length > 0) {
        res.json({ success: false, message: "Email already registered" });
      } else {
        const otp = generateOTP();
        db.query(
          "INSERT INTO otps (email, otp) VALUES (?, ?)",
          [email, otp],
          (err, result) => {
            if (err) {
              res.status(500).json({ error: err.message });
            } else {
              sendOTP(email, otp);
              res.json({ success: true, message: "OTP sent to your email" });
            }
          }
        );
      }
    }
  );
});

app.post("/update-rolebased", (req, res) => {
  const { email, username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.query(
    "UPDATE rolebased SET username = ?, password = ? WHERE email = ?",
    [username, hashedPassword, email],
    (err, results) => {
      if (err) {
        console.error("Error updating rolebased:", err.message);
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        res.json({
          success: true,
          message: "User details updated successfully",
        });
      }
    }
  );
});
const generateNextUsername = (callback) => {
  db.query(
    "SELECT username FROM rolebased ORDER BY id DESC LIMIT 1",
    (err, results) => {
      if (err) {
        return callback(err, null);
      }
      let nextUsername;
      if (results.length > 0) {
        const lastUsername = results[0].username;
        const numberPart = parseInt(lastUsername.replace("user", ""), 10);
        if (isNaN(numberPart)) {
          nextUsername = "user000001";
        } else {
          nextUsername = "user" + String(numberPart + 1).padStart(6, "0");
        }
      } else {
        nextUsername = "user000001";
      }
      callback(null, nextUsername);
    }
  );
};
app.post("/verify", (req, res) => {
  const { email, otp } = req.body;
  db.query(
    "SELECT * FROM otps WHERE email = ? AND otp = ?",
    [email, otp],
    async (err, results) => {
      if (err) {
        console.error("Error fetching OTP:", err.message);
        res.status(500).json({ error: "Internal Server Error" });
      } else if (results.length > 0) {
        // Check if the email already exists in the rolebased table
        db.query(
          "SELECT * FROM rolebased WHERE email = ?",
          [email],
          (err, existingUsers) => {
            if (err) {
              console.error("Error checking existing user:", err.message);
              res.status(500).json({ error: "Internal Server Error" });
            } else if (existingUsers.length > 0) {
              res
                .status(400)
                .json({ success: false, message: "Email already registered" });
            } else {
              // Generate the next username
              generateNextUsername((err, username) => {
                if (err) {
                  console.error("Error generating username:", err.message);
                  res.status(500).json({ error: "Internal Server Error" });
                } else {
                  const role = "masteradmin";
                  const token = jwt.sign({ email, role }, jwtSecretKey, {
                    expiresIn: "30m",
                  });
                  res.cookie("token", token, { httpOnly: true });

                  // Generate password
                  const password = Math.random().toString(36).slice(-8);
                  const hashedPassword = bcrypt.hashSync(password, 10);

                  // Insert into rolebased table
                  db.query(
                    "INSERT INTO rolebased (email, username, password, role ,Status ) VALUES (?, ?, ?, ?, ?)",
                    [email, username, hashedPassword, role,'Active'],
                    (err, results) => {
                      if (err) {
                        console.error(
                          "Error inserting into rolebased:",
                          err.message
                        );
                        res
                          .status(500)
                          .json({ error: "Internal Server Error" });
                      } else {
                        // Send welcome email
                        sendWelcomeEmail(email, username, password);
                        res.json({
                          success: true,
                          message: "OTP verified",
                          token,
                          role,
                          username,
                          password,
                        });
                      }
                    }
                  );
                }
              });
            }
          }
        );
      } else {
        console.error("Invalid OTP for email:", email);
        res.json({ success: false, message: "Invalid OTP" });
      }
    }
  );
});
app.post("/google-login", (req, res) => {
  const { credentialResponse } = req.body;
  if (credentialResponse) {
    const token = jwt.sign({ email: credentialResponse.email }, "secret", {
      expiresIn: "30min",
    });
    res.json({ token });
  } else {
    res.status(401).json({ message: "Google login failed" });
  }
});

app.post("/loginnn", async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query =
      "INSERT INTO rolebased (username, password, role) VALUES (?, ?, ?)";
    db.query(query, [username, hashedPassword, role], (err, result) => {
      if (err) {
        res
          .status(500)
          .json({ success: false, message: "Error inserting data" });
      } else {
        res.json({
          success: true,
          message: "Login data saved successfully",
          role,
        });
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error hashing password" });
  }
});

// login signup inside start
app.post('/login', async (req, res) => {
  const { username, password, role, email } = req.body;

  try {
    // Check if email is already registered
    const checkEmailQuery = 'SELECT * FROM rolebased WHERE email = ?';
    db.query(checkEmailQuery, [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Error checking email' });
      }

      if (results.length > 0) {
        return res.status(400).json({ success: false, message: 'Email is already registered' });
      }
      const checkUsernameQuery = 'SELECT * FROM rolebased WHERE username = ?';
      db.query(checkUsernameQuery, [username], async (err, usernameResults) => {
        if (err) {
          return res.status(500).json({ success: false, message: 'Error checking username' });
        }

        if (usernameResults.length > 0) {
          return res.status(400).json({ success: false, message: 'Username is already taken' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery = 'INSERT INTO rolebased (username, password, role, email) VALUES (?, ?, ?, ?)';
        db.query(insertQuery, [username, hashedPassword, role, email], (err, result) => {
          if (err) {
            res.status(500).json({ success: false, message: 'Error inserting data' });
          } else {
            res.json({ success: true, message: 'Login data saved successfully', role });
          }
        });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error processing request' });
  }
});
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000);
}

function sendOTP(email, otp) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "xxxxxxxxxxxx@gmail.com",
      pass: "xxxxxxxxxxxxx",
    },
  });
 
  const mailOptions = {
    from: "xxxxxxxxx@gmail.com",
    to: email,
    subject: "OTP for Login",
    text: `Your OTP for login is: ${otp}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}

app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const userQuery = 'SELECT * FROM rolebased WHERE email = ?';
    db.query(userQuery, [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Error checking email' });
      }

      if (results.length === 0) {
        return res.status(400).json({ success: false, message: 'Email is not registered' });
      }

      const storedOTP = results[0].otp;
      if (otp === storedOTP) {
        res.json({ success: true, message: 'OTP verified successfully' });
      } else {
        res.status(400).json({ success: false, message: 'Invalid OTP' });
      }
    });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ success: false, message: 'An error occurred while verifying OTP' });
  }
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const userQuery = 'SELECT * FROM rolebased WHERE email = ?';
    db.query(userQuery, [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Error checking email' });
      }

      if (results.length === 0) {
        return res.status(400).json({ success: false, message: 'Email is not registered' });
      }

      const otp = generateOTP();
      const updateQuery = 'UPDATE rolebased SET otp = ? WHERE email = ?';
      db.query(updateQuery, [otp, email], async (err, updateResult) => {
        if (err) {
          return res.status(500).json({ success: false, message: 'Error updating OTP' });
        }

        sendOTP(email, otp);
        res.json({ success: true, message: 'OTP sent to your email for password reset' });
      });
    });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ success: false, message: 'An error occurred while sending OTP' });
  }
});

app.post('/change-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.query(
      'UPDATE rolebased SET password = ? WHERE email = ?',
      [hashedPassword, email],
      (error, results, fields) => {
        if (error) {
          console.error('Error updating password:', error);
          return res.status(500).json({ success: false, message: 'Failed to update password.' });
        }
        res.status(200).json({ success: true, message: 'Password updated successfully.' });
      }
    );
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ success: false, message: 'Failed to update password.' });
  }
});
// login signup inside end 

function verifyToken(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  jwt.verify(token.split(" ")[1], jwtSecretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    req.user = decoded;
    next();
  });
}

app.get("/masteradmin", verifyToken, (req, res) => {
  const user = req.user;
  res.json({
    success: true,
    message: `Hello, ${user.username}! You have access to this protected route.`,
  });
});

app.get("/employee", verifyToken, (req, res) => {
  const user = req.user;
  res.json({
    success: true,
    message: `Hello, ${user.username}! You have access to this protected route.`,
  });
});

app.post("/loginn", (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM rolebased WHERE username = ?`;

  db.query(query, [username], async (error, results) => {
    if (error) {
      res.status(500).json({ success: false, message: "Database error" });
    } else if (results.length > 0) {
      const user = results[0];
      
      if (user.Status === 'Deactive') {
        res.json({ success: false, message: "This account is deactivated. Please contact support." });
      } else {
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
          const role = user.role;
          const token = jwt.sign({ username, role }, jwtSecretKey, {
            expiresIn: "30m",
          });
          res.cookie("token", token, { httpOnly: true });
          res.json({ success: true, role, token });
        } else {
          res.json({ success: false, message: "Invalid credentials" });
        }
      }
    } else {
      res.json({ success: false, message: "Invalid credentials" });
    }
  });
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true, message: "Logged out successfully" });
});

app.get("/loginn", (req, res) => {
  const query = "SELECT * FROM rolebased";
  db.query(query, (error, results) => {
    if (error) {
      res
        .status(500)
        .json({ success: false, message: "Error fetching user data" });
    } else {
      res.json({ success: true, users: results });
    }
  });
});
// submit form start
app.post("/submit-form", (req, res) => {
  const { name, phoneNumber, email, website, message } = req.body;
  const sql = `INSERT INTO contact_form (name, phone_number, email, website, message) VALUES (?, ?, ?, ?, ?)`;

  db.query(sql, [name, phoneNumber, email, website, message], (err, result) => {
    if (err) {
      console.error("Error submitting form:", err);
      return res.status(500).json({
        success: false,
        message: "An error occurred while submitting the form",
      });
    }
    return res
      .status(200)
      .json({ success: true, message: "Form submitted successfully" });
  });
});
app.post("/submit-partner-form", (req, res) => {
  const { name, phoneNumber, email, profession, message } = req.body;
  const sql = `INSERT INTO partner_form (name, phone_number, email, profession, message) VALUES (?, ?, ?, ?, ?)`;

  db.query(
    sql,
    [name, phoneNumber, email, profession, message],
    (err, result) => {
      if (err) {
        console.error("Error submitting partner form:", err);
        return res.status(500).json({
          success: false,
          message: "An error occurred while submitting the partner form",
        });
      }
      return res.status(200).json({
        success: true,
        message: "Partner form submitted successfully",
      });
    }
  );
});
// submit form end
//  categories start
app.post("/categories", verifyToken, (req, res) => {
  const { name, dataandtime, username } = req.body;

  // Fetch existing categories for the user
  const sqlFetch = "SELECT * FROM categories WHERE username = ?";
  db.query(sqlFetch, [username], (err, results) => {
    if (err) {
      console.error("Error fetching categories: ", err);
      res.status(500).send("Error adding category");
      return;
    }
    const maxCategoryId = results.reduce(
      (maxId, category) => Math.max(maxId, category.category_id),
      0
    );
    const category_id = maxCategoryId + 1;

    const sqlInsert =
      "INSERT INTO categories (category_id, name, dataandtime, username) VALUES (?, ?, ?, ?)";
    db.query(
      sqlInsert,
      [category_id, name, dataandtime, username],
      (err, result) => {
        if (err) {
          console.error("Error adding category: ", err);
          res.status(500).send("Error adding category");
          return;
        }
        res.send("Category added successfully");
      }
    );
  });
});

app.get("/categories", verifyToken, (req, res) => {
  const username = req.user.username;
  const sql = "SELECT * FROM categories WHERE username = ?";
  db.query(sql, [username], (err, results) => {
    if (err) {res
      console.error("Error fetching categories: ", err);
      res.status(500).send("Error fetching categories");
      return;
    }
    res.json(results);
  });
});

app.put("/categories/:id", (req, res) => {
  const categoryId = req.params.id;
  const { name, dataandtime } = req.body;
  const sql = "UPDATE categories SET name = ?, dataandtime = ? WHERE id = ?";
  db.query(sql, [name, dataandtime, categoryId], (err, result) => {
    if (err) {
      console.error("Error updating category: ", err);
      res.status(500).send("Error updating category");
      return;
    }
    res.send("Category updated successfully");
  });
});
app.delete("/categories/:id", (req, res) => {
  const categoryId = req.params.id;
  const sql = "DELETE FROM categories WHERE id = ?";
  db.query(sql, [categoryId], (err, result) => {
    if (err) {
      console.error("Error deleting category: ", err);
      res.status(500).send("Error deleting category");
      return;
    }
    res.send("Category deleted successfully");
  });
});
//  categories end

// supplier start
app.post("/supplier", verifyToken, (req, res) => {
  const { supplierName, contactInfo } = req.body;
  const dateandtime = new Date().toISOString().slice(0, 19).replace("T", " ");
  const username = req.user.username;

  // Fetch existing suppliers for the user to determine the next supplierID
  const sqlFetch = "SELECT * FROM supplier WHERE username = ?";
  db.query(sqlFetch, [username], (err, results) => {
    if (err) {
      console.error("Error fetching suppliers: ", err);
      res.status(500).send("Error adding supplier");
      return;
    }
    const maxSupplierId = results.reduce(
      (maxId, supplier) => Math.max(maxId, supplier.supplierID),
      0
    );
    const supplierID = maxSupplierId + 1;

    // Insert the new supplier
    const sqlInsert =
      "INSERT INTO supplier (supplierID, supplierName, contactInfo, dateandtime, username) VALUES (?, ?, ?, ?, ?)";
    db.query(
      sqlInsert,
      [supplierID, supplierName, contactInfo, dateandtime, username],
      (err, result) => {
        if (err) {
          console.error("Error adding supplier: ", err);
          res.status(500).send("Error adding supplier");
          return;
        }
        res.send("Supplier added successfully");
      }
    );
  });
});

app.get("/supplier", verifyToken, (req, res) => {
  const username = req.user.username;
  const sql = "SELECT * FROM supplier WHERE username = ?";
  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error fetching suppliers: ", err);
      res.status(500).send("Error fetching suppliers");
      return;
    }
    res.json(results);
  });
});

app.put("/supplier/:supplierID", (req, res) => {
  const { supplierID } = req.params;
  const { supplierName, contactInfo, dateandtime } = req.body;

  const sql =
    "UPDATE supplier SET supplierName = ?, contactInfo = ?, dateandtime = ? WHERE supplierID = ?";
  db.query(
    sql,
    [supplierName, contactInfo, dateandtime, supplierID],
    (err, result) => {
      if (err) {
        console.error("Error updating supplier: ", err);
        res.status(500).send("Error updating supplier");
        return;
      }
      res.send("Supplier updated successfully");
    }
  );
});

app.delete("/supplier/:supplierID", (req, res) => {
  const { supplierID } = req.params;

  const sql = "DELETE FROM supplier WHERE supplierID = ?";
  db.query(sql, [supplierID], (err, result) => {
    if (err) {
      console.error("Error deleting supplier: ", err);
      res.status(500).send("Error deleting supplier");
      return;
    }
    res.send("Supplier deleted successfully");
  });
});

// supplier end

// products start
app.get("/api/categories", verifyToken, (req, res) => {
  const { username } = req.user;
  const sql = `
  SELECT name 
  FROM categories 
  WHERE username = ?`;
  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error fetching categories: ", err);
      res.status(500).send("Error fetching categories");
      return;
    }
    const categoryNames = results.map((category) => category.name);
    res.json(categoryNames);
  });
});

app.post("/api/products", verifyToken, (req, res) => {
  const {
    productName,
    category,
    description,
    SKU,
    weight,
    unit,
    sellingPrice,
    mrp,
    salesDescription,
    barcode,
    dateTime,
    username, // Include username
  } = req.body;

  // Fetch existing products for the user
  const sqlFetch = "SELECT * FROM products WHERE username = ?";
  db.query(sqlFetch, [username], (err, results) => {
    if (err) {
      console.error("Error fetching products: ", err);
      res.status(500).send("Error adding product");
      return;
    }
    const maxProductId = results.reduce(
      (maxId, product) => Math.max(maxId, product.productId),
      0
    );
    const productId = maxProductId + 1;

    const sqlInsert =
      "INSERT INTO products (productId, productName, category, description, SKU, weight, unit, sellingPrice, mrp, salesDescription, barcode, dateTime, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    db.query(
      sqlInsert,
      [
        productId,
        productName,
        category,
        description,
        SKU,
        weight,
        unit,
        sellingPrice,
        mrp,
        salesDescription,
        barcode,
        dateTime,
        username,
      ],
      (err, result) => {
        if (err) {
          console.error("Error inserting product:", err);
          res.status(500).json({ error: "Internal server error" });
          return;
        }
        res.status(200).json({ message: "Product inserted successfully" });
      }
    );
  });
});

app.get("/api/products", verifyToken, (req, res) => {
  const username = req.user ? req.user.username : null;
  if (!username) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const sql = "SELECT * FROM products WHERE username = ?";
  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error retrieving products:", err);
      res.status(500).json({ error: "Internal server error" });
      return;
    }

    res.status(200).json(results);
  });
});

app.put("/products/:productId", (req, res) => {
  const { productId } = req.params;
  const {
    productName,
    category,
    description,
    SKU,
    weight,
    unit,
    sellingPrice,
    mrp,
    salesDescription,
  } = req.body;

  const sql =
    "UPDATE products SET productName = ?, category = ?, description = ?, SKU = ?, weight = ?, unit = ?, sellingPrice = ?, mrp = ?, salesDescription = ?  WHERE productId = ?  ";
  db.query(
    sql,
    [
      productName,
      category,
      description,
      SKU,
      weight,
      unit,
      sellingPrice,
      mrp,
      salesDescription,
      productId,
    ],
    (err, result) => {
      if (err) {
        console.error("Error updating product: ", err);
        res.status(500).send("Error updating product");
        return;
      }
      res.send("Product updated successfully");
    }
  );
});
app.delete("/api/products/:productId", (req, res) => {
  const { productId } = req.params;
  const sql = "DELETE FROM products WHERE productId = ?";
  db.query(sql, [productId], (err, result) => {
    if (err) {
      console.error("Error deleting product: ", err);
      res.status(500).send("Error deleting product");
      return;
    }
    res.send("Product deleted successfully");
  });
});

// products end

// employeeinfo 



// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: "xxxxxxxxxxxx@gmail.com",
    pass: "xxxxxxxxxxxx",
  },
});



//fetch employees according to the username
app.get('/employees', (req, res) => {
  const token = req.cookies.token;

  try {
    const decodedToken = jwt.verify(token, jwtSecretKey);
    const masteradmin = decodedToken.username;

    const fetchEmployeesQuery = 'SELECT * FROM employee_form WHERE masteradmin = ?';
    db.query(fetchEmployeesQuery, [masteradmin], (err, results) => {
      if (err) {
        console.error('Error fetching employees:', err);
        res.status(500).send('Error fetching employees');
      } else {
        res.status(200).json(results);
      }
    });
  } catch (error) {
    console.error("JWT verification error:", error.message);
    res.status(401).json({ error: "Invalid token" });
  }
});
//



//to add date and time and masteradmin loged in username
app.post('/employee_form', async (req, res) => {
  const {
    Employee_ID,
    Name,
    Contact,
    Email,
    Address,
    position,
    Status,
    role
  } = req.body;

  const token = req.cookies.token;
  let loggedInUsername;
  try {
    const decodedToken = jwt.verify(token, jwtSecretKey);
    loggedInUsername = decodedToken.username;
  } catch (error) {
    console.error("JWT verification error:", error.message);
    return res.status(401).json({ error: "Invalid token" });
  }

  // Generate username and password
  const username = `Emp${String((await getEmployeeCount()) + 1).padStart(4, '0')}`;
  const password = generatePassword();

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  const currentDateTime = new Date().toISOString().slice(0, 19).replace('T', ' ');

  const employeeQuery = `INSERT INTO employee_form (Employee_ID, Name, Contact, Email, Address, position, Password, Username, Status, role, dateTime, masteradmin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  db.query(employeeQuery, [Employee_ID, Name, Contact, Email, Address, position, hashedPassword, username, Status, role, currentDateTime, loggedInUsername], async (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).send('Failed to add employee');
    } else {
      // Insert into rolebased table
      const rolebasedQuery = `INSERT INTO rolebased (username, password, email, role, Status) VALUES (?, ?, ?, ?, 'active')`;

      db.query(rolebasedQuery, [username, hashedPassword, Email, 'employee'], async (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).send('Failed to add employee credentials to rolebased table');
        } else {
          // Send email with credentials
          try {
            await sendCredentialsEmail(Name, Email, username, password);
            console.log('Email sent successfully');
            res.status(200).send('Employee added and email sent successfully');
          } catch (error) {
            console.error('Error sending email:', error);
            res.status(500).send('Failed to send email');
          }
        }
      });
    }
  });
});

//

// Function to get employee count
const getEmployeeCount = () => {
  return new Promise((resolve, reject) => {
    const countQuery = `SELECT COUNT(*) AS count FROM employee_form`;
    db.query(countQuery, (err, result) => {
      if (err) reject(err);
      resolve(result[0].count);
    });
  });
};

// Function to generate a random password
const generatePassword = () => {
  const length = 8;
  const charset = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  let password = "";
  for (let i = 0; i < length; ++i) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return password;
};

// Function to send email with credentials
const sendCredentialsEmail = (name, email, username, password) => {
  const mailOptions = {
    from: 'your_email@gmail.com',
    to: email,
    subject: 'Your Employee Credentials',
    text: `Dear ${name},\n\nYour employee account has been created successfully. Here are your login credentials:\n\nUsername: ${username}\nPassword: ${password}\n\nPlease keep this information secure.\n\nBest regards,\nYour Company`
  };

  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
};


//for emp id 


//after submitting and after refresh latest number get
app.get('/get-max-employee-id', async (req, res) => {
  const token = req.cookies.token;
  try {
    const decodedToken = jwt.verify(token, jwtSecretKey);
    const username = decodedToken.username;

    const query = "SELECT business_name FROM masteradmin_popupForm WHERE username = ? ORDER BY created_at DESC LIMIT 1";

    db.query(query, [username], (err, results) => {
      if (err) {
        console.error("Error fetching business name:", err.message);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: "No business name found for this user" });
      }

      const businessName = results[0].business_name;

      const maxIdQuery = `SELECT MAX(CAST(SUBSTRING(Employee_ID, LENGTH(?) + 2, LENGTH(Employee_ID)) AS UNSIGNED)) AS maxId
                          FROM employee_form
                          WHERE Employee_ID LIKE ?`;

      db.query(maxIdQuery, [businessName, `${businessName}_%`], (err, results) => {
        if (err) {
          console.error("Error fetching max employee ID:", err.message);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        const maxId = results[0].maxId ? results[0].maxId : 0;
        res.status(200).json({ maxId });
      });
    });
  } catch (error) {
    console.error("JWT verification error:", error.message);
    res.status(401).json({ error: "Invalid token" });
  }
});


//


// PUT endpoint to update an employee
app.put("/employees", (req, res) => {
  const {
    Employee_ID,
    Name,
    Contact,
    Email,
    Address,
    position,
    Status,
    Username,
    Password,
    role,
    dateTime
  } = req.body;

  const updateQuery = `
    UPDATE employee_form
    SET
      Name = ?,
      Contact = ?,
      Email = ?,
      Address = ?,
      position = ?,
      Status = ?,
      Username = ?,
      Password = ?,
      role = ?,
      dateTime = ?
    WHERE Employee_ID = ?
  `;

  const values = [
    Name,
    Contact,
    Email,
    Address,
    position,
    Status,
    Username,
    Password,
    role,
    dateTime,
    Employee_ID
  ];

  db.query(updateQuery, values, (error, results) => {
    if (error) {
      console.error("Error updating employee:", error);
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      res.status(200).json({ message: "Employee updated successfully" });
    }
  });
});

// DELETE endpoint to delete an employee
app.delete("/employees/:id", (req, res) => {
  const employeeId = req.params.id;

  const deleteQuery = "DELETE FROM employee_form WHERE id = ?";
  db.query(deleteQuery, [employeeId], (err, result) => {
    if (err) {
      console.error("Error deleting employee:", err);
      res.status(500).json({ error: "Error deleting employee" });
    } else {
      res.status(200).json({ message: "Employee deleted successfully" });
    }
  });
});


//employee info ended

// purchaseorder start
app.get("/api/suppliers", verifyToken, (req, res) => {
  const username = req.user.username;
  const sql = "SELECT supplierName FROM supplier WHERE username = ?";
  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error fetching suppliers: ", err);
      res.status(500).json({ error: "Error fetching suppliers" });
      return;
    }
    const supplierData = results.map((supplier) => supplier.supplierName);
    res.json(supplierData);
  });
});

app.get("/api/productss", verifyToken, (req, res) => {
  const username = req.user.username;
  const searchTerm = req.query.searchTerm;
  let sql = "SELECT productName FROM products WHERE username = ?";
  const queryParams = [username];

  if (searchTerm) {
    sql += " AND productName LIKE ?";
    queryParams.push(`%${searchTerm}%`);
  }

  db.query(sql, queryParams, (err, results) => {
    if (err) {
      console.error("Error fetching products: ", err);
      res.status(500).send("Error fetching products");
      return;
    }
    const productNames = results.map((product) => product.productName);
    res.json(productNames);
  });
});

app.get("/api/productts/:searchTerm", verifyToken, (req, res) => {
  const { searchTerm } = req.params;
  const username = req.user.username;
  const sql =
    "SELECT productId FROM products WHERE productName = ? AND username = ?";

  db.query(sql, [searchTerm, username], (err, results) => {
    if (err) {
      console.error("Error retrieving products:", err);
      res.status(500).json({ error: "Internal server error" });
      return;
    }

    res.status(200).json(results);
  });
});

app.post("/api/purchase-orders", (req, res) => {
  const { purchaseInvoiceId, SupplierName, paymentType, products, username } =
    req.body;

  // Query to get the last used invoiceId
  const getInvoiceIdSql =
    "SELECT MAX(invoiceId) AS lastInvoiceId FROM purchase_orders";

  db.query(getInvoiceIdSql, (err, results) => {
    if (err) {
      console.error("Error fetching last invoice ID:", err);
      res.status(500).json({ error: "Error fetching last invoice ID" });
      return;
    }

    const lastInvoiceId = results[0].lastInvoiceId || 0;
    const newInvoiceId = lastInvoiceId + 1;

    // Construct SQL query to insert data into the purchase_orders table
    const insertSql = `
      INSERT INTO purchase_orders (invoiceId, purchaseInvoiceId, SupplierName, paymentType, productId, productName, quantity, price, discount, unit, username)
      VALUES ?
    `;

    // Convert products array into an array of arrays
    const values = products.map((product) => [
      newInvoiceId,
      purchaseInvoiceId,
      SupplierName,
      paymentType,
      product.productId,
      product.productName,
      product.quantity,
      product.price,
      product.discount,
      product.unit,
      username,
    ]);

    db.query(insertSql, [values], (err, results) => {
      if (err) {
        console.error("Error inserting purchase order:", err);
        res.status(500).json({ error: "Error inserting purchase order" });
        return;
      }

      res
        .status(200)
        .json({
          message: "Purchase order created successfully",
          invoiceId: newInvoiceId,
        });
    });
  });
});

// purchaseorder end
app.get('/api/sales-invoices', verifyToken, (req, res) => {
  const username = req.user ? req.user.username : null;

  if (!username) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const selectSalesInvoices = `
    SELECT * FROM sales_invoices WHERE username = ?
  `;

  db.query(selectSalesInvoices, [username], (err, results) => {
    if (err) {
      console.error('Error fetching sales invoices:', err);
      res.status(500).json({ error: 'Failed to fetch sales invoices' });
    } else {
      res.status(200).json(results);
    }
  });
});
// sales order start
app.get("/api/sale-orders",  (req, res) => {
  const { productName, username } = req.query;

  let sql = `SELECT productId, productName, price FROM purchase_orders WHERE username = ?`;

  if (productName) {
    sql += ` AND productName LIKE ?`;
  }

  const queryValues = [username];
  if (productName) {
    queryValues.push(`%${productName}%`);
  }

  db.query(sql, queryValues, (err, results) => {
    if (err) {
      console.error("Error fetching purchase orders:", err);
      res.status(500).json({ error: "Error fetching purchase orders" });
    } else {
      res.status(200).json(results);
    }
  });
});

app.get("/api/product-details", (req, res) => {
  const { barcode, username } = req.query;

  let sql = `SELECT productId, productName, sellingPrice FROM products WHERE username = ?`;

  if (barcode) {
    sql += ` AND barcode = ?`;
  }

  const queryValues = [username];
  if (barcode) {
    queryValues.push(barcode);
  }

  db.query(sql, queryValues, (err, results) => {
    if (err) {
      console.error("Error fetching product details:", err);
      res.status(500).json({ error: "Error fetching product details" });
    } else {
      res.status(200).json(results);
    }
  });
});

app.post("/api/save-sales-invoice", (req, res) => {
  const { customerName, phoneNumber, paymentMethod, products, username } =
    req.body;
    console.log("Received products:", products);
  // Calculate total price for the entire invoice
  const totalPrice = products.reduce(
    (acc, product) => acc + product.quantity * product.price,
    0
  );

  // Query to get the last used saleInvoiceId
  const getSaleInvoiceIdSql =
    "SELECT MAX(saleInvoiceId) AS lastSaleInvoiceId FROM sales_invoices";

  db.query(getSaleInvoiceIdSql, (error, results) => {
    if (error) {
      console.error("Error fetching last sale invoice ID:", error);
      res.status(500).json({ message: "Internal server error" });
      return;
    }

    const lastSaleInvoiceId = results[0].lastSaleInvoiceId || 0;
    const newSaleInvoiceId = lastSaleInvoiceId + 1;

    // Construct SQL query to insert data into the sales_invoices table
    const insertSql = `
      INSERT INTO sales_invoices (saleInvoiceId, customerName, phoneNumber, paymentMethod, productId, productName, quantity, price, totalAmount, totalPrice, username)
      VALUES ?
    `;

    // Convert products array into an array of arrays
    const values = products.map((product) => [
      newSaleInvoiceId,
      customerName,
      phoneNumber,
      paymentMethod,
      product.productId,
      product.productName,
      product.quantity,
      product.price,
      product.quantity * product.price, // Calculating total price per product
      totalPrice, // Total price for the entire invoice
      username,
    ]);

    db.query(insertSql, [values], (error, results, fields) => {
      if (error) {
        console.error("Error inserting sales invoice data:", error);
        res.status(500).json({ message: "Internal server error" });
        return;
      }

      res.status(200).json({
        message: "Sales invoice data saved successfully",
        saleInvoiceId: newSaleInvoiceId,
      });
    });
  });
});

// sales order end

// starting page start

// starting page end

app.post("/saveCustomer", verifyToken, (req, res) => {
  const { username, ...customerData } = req.body;
  customerData.username = username;

  const sql = "INSERT INTO customer_data SET ?";

  db.query(sql, customerData, (err, result) => {
    if (err) {
      console.error("Error saving customer data:", err);
      res.status(500).send("Error saving customer data");
      return;
    }
    console.log("Customer data saved successfully");
    res.status(200).send("Customer data saved successfully");
  });
});

// Fetch customer data for a specific user
app.get("/saveCustomer", verifyToken, (req, res) => {
  const username = req.user ? req.user.username : null;

  if (!username) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const sql = "SELECT * FROM customer_data WHERE username = ?";
  db.query(sql, [username], (err, result) => {
    if (err) {
      console.error("Error fetching customer data:", err);
      res.status(500).send("Error fetching customer data");
      return;
    }
    res.status(200).json(result);
  });
});

// Update customer data
app.put("/updateCustomer/:customerId", (req, res) => {
  try {
    const customerId = req.params.customerId;
    const updatedCustomerData = req.body;

    const sql = "UPDATE customer_data SET ? WHERE customerId = ?";

    db.query(sql, [updatedCustomerData, customerId], (err, result) => {
      if (err) {
        console.error("Error updating customer:", err);
        res.status(500).send("Error updating customer");
        return;
      }
      console.log("Customer updated successfully");
      res.status(200).send("Customer updated successfully");
    });
  } catch (error) {
    console.error("Error updating customer:", error);
    res.status(500).send("Error updating customer");
  }api/employee-form
});

// Delete a customer by ID
app.delete("/deleteCustomer/:customerId", (req, res) => {
  const customerId = req.params.customerId;

  const sql = "DELETE FROM customer_data WHERE customerId = ?";

  db.query(sql, customerId, (err, result) => {
    if (err) {
      console.error("Error deleting customer:", err);
      res.status(500).send("Error deleting customer");
      return;
    }
    console.log("Customer deleted successfully");
    res.status(200).send("Customer deleted successfully");
  });
});

// customer data end here

// invoices sub module is started from here

app.get("/api/invoice/:invoiceId", verifyToken, (req, res) => {
  const { invoiceId } = req.params;
  const username = req.user ? req.user.username : null;

  const sql = `SELECT * FROM sales_invoices WHERE saleInvoiceId = ? AND username = ?`;
  db.query(sql, [invoiceId, username], (err, results) => {
    if (err) {
      console.error("Error fetching invoice details:", err);
      res.status(500).json({ error: "Error fetching invoice details" });
    } else {
      if (results.length > 0) {
        res.status(200).json(results);
      } else {
        res.status(404).json({ error: "Invoice not found" });
      }
    }
  });
});

//invoices sub module was ended here

//to insert username to the masteradmin popupForm

app.post("/submit-business-form", async (req, res) => {
  const {
    businessName,
    businessType,
    otherBusinessType,
    phone,
    email,
    addressLine1,
    addressLine2,
    city,
    state,
    zipCode,
    website,
  } = req.body;

  const createdAt = new Date();

  // Check if the email exists in the rolebased table and get the username
  db.query(
    "SELECT username FROM rolebased WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        console.error("Error fetching username:", err.message);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (results.length === 0) {
        return res
          .status(400)
          .json({ error: "Email not registered in rolebased" });
      }

      const username = results[0].username;

      // Insert form data into masteradmin_popupForm table
      const insertFormQuery = `
      INSERT INTO masteradmin_popupForm (
        username, business_name, business_type, other_business_type, phone, email,
        address_line1, address_line2, city, state, zip_code, website, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

      db.query(
        insertFormQuery,
        [
          username,
          businessName,
          businessType,
          otherBusinessType,
          phone,
          email,
          addressLine1,
          addressLine2,
          city,
          state,
          zipCode,
          website,
          createdAt,
        ],
        (err, results) => {
          if (err) {
            console.error(
              "Error inserting data into masteradmin_popupForm:",
              err
            );
            return res
              .status(500)
              .json({
                error:
                  "Internal Server Error: Could not insert into masteradmin_popupForm",
              });
          }

          res
            .status(200)
            .json({ message: "Business form submitted successfully" });
        }
      );
    }
  );
});

// masteradmin popupform ended

//for welcome mail after succussful signup

// Setup nodemailer transporter
const transporters = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "vamseedhar151@gmail.com",
    pass: "hyskokcgnohwhlqr",
  },
});

function sendWelcomeEmail(email, username, password) {
  const mailOptions = {
    from: "your_email@gmail.com",
    to: email,
    subject: "Welcome to QuickRetail",
    text: `Hello!\n\nWelcome to QuickRetail.\n\nYour credentials are:\nUsername: ${username}\nPassword: ${password}\n\nBest Regards,\nQuickRetail Team`,
  };

  transporters.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending welcome email:", error);
    } else {
      console.log("Welcome email sent: " + info.response);
    }
  });
}

// welcome mail ended

// business profile in settings started

// Endpoint to fetch user details
app.get('/api/fetch-user-details/:username', (req, res) => {
    const username = req.params.username;
  
    const businessProfileQuery = 'SELECT * FROM masteradmin_popupForm WHERE username = ?';
    const passwordQuery = 'SELECT password FROM rolebased WHERE username = ?';
  
    db.query(businessProfileQuery, [username], (err, businessProfileResults) => {
      if (err) {
        console.error('Error fetching business profile from database:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
  
      if (businessProfileResults.length === 0) {
        return res.status(404).json({ error: 'Business profile not found' });
      }
  
      const businessProfile = businessProfileResults[0];
  
      db.query(passwordQuery, [username], (err, passwordResults) => {
        if (err) {
          console.error('Error fetching password from database:', err);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
  
        if (passwordResults.length === 0) {
          return res.status(404).json({ error: 'User credentials not found' });
        }
  
        const hashedPassword = passwordResults[0].password;
  
        // Send business profile data and hashed password as JSON response
        res.status(200).json({ ...businessProfile, username, password: hashedPassword });
      });
    });
  });
  


// Endpoint to update business profile
app.put("/api/updateBusinessProfile", async (req, res) => {
  const {
    username,
    business_name,
    business_type,
    address_line1,
    address_line2,
    city,
    state,
    zip_code,
    phone,
    email,
    website,
    created_at,
  } = req.body;

  try {
    const query = `
      UPDATE masteradmin_popupForm
      SET business_name = ?, business_type = ?, address_line1 = ?, address_line2 = ?,
          city = ?, state = ?, zip_code = ?, phone = ?, email = ?, website = ?, created_at = ?
      WHERE username = ?
    `;

    db.query(
      query,
      [
        business_name,
        business_type,
        address_line1,
        address_line2,
        city,
        state,
        zip_code,
        phone,
        email,
        website,
        created_at,
        username,
      ],
      (err, results) => {
        if (err) {
          console.error("Error updating business profile:", err.message);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        if (results.affectedRows === 0) {
          return res.status(404).json({ error: "User not found" });
        }

        res
          .status(200)
          .json({ message: "Business profile updated successfully" });
      }
    );
  } catch (err) {
    console.error("Error updating business profile:", err.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// business profile in settings ended




// payment gateway start
app.post("/order", async (req, res) => {
  try {
    const razorpay = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_SECRET,
    });

    const options = req.body;
    const order = await razorpay.orders.create(options);

    if (!order) {
      return res.status(500).send("Error creating order");
    }

    res.json(order);
  } catch (err) {
    console.error("Error in /order endpoint:", err);
    res.status(500).send("Error");
  }
});


app.post("/order/validate", async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
    req.body;

  const sha = crypto.createHmac("sha256", process.env.RAZORPAY_SECRET);
  //order_id + "|" + razorpay_payment_id
  sha.update(`${razorpay_order_id}|${razorpay_payment_id}`);
  const digest = sha.digest("hex");
  if (digest !== razorpay_signature) {
    return res.status(400).json({ msg: "Transaction is not legit!" });
  }

  res.json({
    msg: "success",
    orderId: razorpay_order_id,
    paymentId: razorpay_payment_id,
  });
});

// payment gateway end


// superadmin start
app.post('/api/Chatbot', (req, res) => {
  console.log("Received data:", req.body);
  const { Name, Phone, Email, Question1, Question2, Question3, Question4, Question5, Question6, Question7, Question8 } = req.body;
 
  const sql = 'INSERT INTO Chatbot (Name, Phone, Email, Question1, Question2, Question3, Question4, Question5, Question6, Question7, Question8) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
  const values = [Name, Phone, Email, Question1, Question2, Question3, Question4, Question5, Question6, Question7, Question8];
 
  db.query(sql, values, (err, results) => {
    if (err) {
      console.error('Error inserting data: ' + err.stack);
      return res.status(500).send('Error inserting data');
    }
    res.status(200).send('Data inserted successfully');
  });
});
 
 
app.get('/api/Chatbot', (req, res) => {
  const sqlGet = 'SELECT * FROM Chatbot';
  db.query(sqlGet, (error, result) => {
    if (error) {
      return res.status(500).send(error);
    }
    res.send(result);
  });
});
// Chatbot page end
 
// API endpoint to get employee form data
app.get('/api/employee_form', (req, res) => {
  const { date, startDate, endDate, sort } = req.query;
 
  let sqlQuery = 'SELECT * FROM employee_form';
  let queryParams = [];
 
  if (date) {
    sqlQuery += ' WHERE DATE(dateTime) = ?';  // Ensure the DATE() function is used if `dateTime` is DATETIME type
    queryParams.push(date);
  } else if (startDate && endDate) {
    sqlQuery += ' WHERE DATE(dateTime) BETWEEN ? AND ?';  // Ensure the DATE() function is used if `dateTime` is DATETIME type
    queryParams.push(startDate, endDate);
  }
 
  if (sort) {
    // Convert sort values to SQL keywords
    const sortOrder = sort === 'Ascending' ? 'ASC' : 'DESC';
    sqlQuery += ` ORDER BY Employee_ID ${sortOrder}`;
  }
 
  db.query(sqlQuery, queryParams, (error, result) => {
    if (error) {
      console.error('Error fetching employee_form data:', error);
      return res.status(500).send(error);
    }
    res.send(result);
  });
});

app.put('/api/employee_form/:id', (req, res) => {
  const id = req.params.id;
  const updateFields = req.body;
 
  const fields = Object.keys(updateFields).map(field => `${field} = ?`).join(', ');
  const values = Object.values(updateFields).concat(id);
 
  const sql = `UPDATE employee_form SET ${fields} WHERE id = ?`;
  db.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error updating user: ', err);
      res.status(500).send('Error updating user');
      return;
    }
    console.log('User updated successfully');
    res.json(req.body); 
  });
});
 
 
// API endpoint to get rolebased  data
app.get('/api/rolebased', (req, res) => {
  const sqlGet = 'SELECT * FROM rolebased';
  db.query(sqlGet, (error, result) => {
    if (error) {
      console.error('Error fetching rolebased data:', error);
      return res.status(500).send(error);
    }
    res.send(result);
  });
});
 
 
 
 
app.put('/api/rolebased/:id', (req, res) => {
  const userId = req.params.id;
  const updateFields = req.body;
 
  // Construct SQL dynamically based on provided fields
  const fields = Object.keys(updateFields).map(field => `${field} = ?`).join(', ');
  const values = Object.values(updateFields).concat(userId);
 
  const sql = `UPDATE rolebased SET ${fields} WHERE id = ?`;
  db.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error updating user: ', err);
      res.status(500).send('Error updating user');
      return;
    }
    console.log('User updated successfully');
    res.send('User updated successfully');
  });
});
// superadmin end

// Reports Sales started from here

// Fetch specific sales invoice by ID for a user
app.get("/api/salesInvoices/:invoiceId", verifyToken,(req, res) => {
  const { invoiceId } = req.params;
  const username = req.user ? req.user.username : null;

  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  const sql = `SELECT * FROM sales_invoices WHERE saleInvoiceId = ? AND username = ?`;
  db.query(sql, [invoiceId, username], (err, results) => {
    if (err) {
      console.error("Error fetching sales invoices:", err);
      res.status(500).json({ error: "Error fetching sales invoices" });
    } else {
      res.status(200).json(results);
    }
  });
});

app.get('/api/masteradmin_popupForm/daily', (req, res) => {
  const sqlGetDailyNewUsers = `
    SELECT
      DAY(created_at) AS day,
      COUNT(*) AS newUsers
    FROM
      masteradmin_popupForm
    WHERE
      MONTH(created_at) = MONTH(CURDATE()) AND
      YEAR(created_at) = YEAR(CURDATE())
    GROUP BY
      DAY(created_at)
    ORDER BY
      DAY(created_at)
  `;
  
  app.get('/api/masteradmin_popupForm', (req, res) => {
    const sqlGet = 'SELECT * FROM masteradmin_popupForm';
    db.query(sqlGet, (error, results) => {
      if (error) {
        console.error('Error fetching masteradmin_popupForm data:', error);
        return res.status(500).send(error);
      }
      res.send(results);
    });
  });
   
  app.get('/api/masteradmin_popupForm', async (req, res) => {
    try {
      const { page = 1, limit = 10, search = '' } = req.query;
      const offset = (page - 1) * limit;
     
      const whereClause = {
        [Op.or]: [
          { business_name: { [Op.like]: `%${search}%` } },
          { id: { [Op.like]: `%${search}%` } }
        ]
      };
   
      const { count, rows } = await MasterAdminPopupForm.findAndCountAll({
        where: whereClause,
        limit: parseInt(limit),
        offset: parseInt(offset),
        order: [['id', 'ASC']]
      });
   
      const totalPages = Math.ceil(count / limit);
   
      res.json({
        items: rows,
        totalPages,
      });
    } catch (error) {
      console.error('Error fetching data:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
   
   
  app.get('/api/masteradmin_popupForm/daily', (req, res) => {
    const sqlGetDailyNewUsers = `
      SELECT
        DAY(created_at) AS day,
        COUNT(*) AS newUsers
      FROM
        masteradmin_popupForm
      WHERE
        MONTH(created_at) = MONTH(CURDATE()) AND
        YEAR(created_at) = YEAR(CURDATE())
      GROUP BY
        DAY(created_at)
      ORDER BY
        DAY(created_at)
    `;
   
    db.query(sqlGetDailyNewUsers, (error, results) => {
      if (error) {
        console.error('Error fetching daily new users:', error);
        return res.status(500).send(error);
      }
   
      // Get the total number of days in the current month
      const daysInMonth = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0).getDate();
   
      // Initialize array with zeros for all days of the month
      const dailyNewUsers = new Array(daysInMonth).fill(0);
   
      // Populate the array with results
      results.forEach(result => {
        dailyNewUsers[result.day - 1] = result.newUsers;
      });
   
      res.send(dailyNewUsers);
    });
  });
   
  app.get('/api/sales_invoices/monthly', (req, res) => {
    const sqlGetMonthlyRevenue = `
      SELECT
        MONTH(dateandtime) AS month,
        SUM(totalprice) AS revenue
      FROM
        sales_invoices
      WHERE
        YEAR(dateandtime) = YEAR(CURDATE())
      GROUP BY
        MONTH(dateandtime)
      ORDER BY
        MONTH(dateandtime)
    `;
   
    db.query(sqlGetMonthlyRevenue, (error, results) => {
      if (error) {
        console.error('Error fetching monthly revenue:', error);
        return res.status(500).send(error);
      }
   
      const monthlyRevenue = new Array(12).fill(0);
      results.forEach(result => {
        monthlyRevenue[result.month - 1] = result.revenue;
      });
   
      res.send(monthlyRevenue);
    });
  });
   
   
   
  app.get('/api/rolebased/totalActiveUsers', (req, res) => {
    const sqlGetActiveUsers = 'SELECT COUNT(*) AS totalActiveUsers FROM rolebased WHERE status = "Active"';
    db.query(sqlGetActiveUsers, (error, result) => {
      if (error) {
        console.error('Error fetching active users count:', error);
        return res.status(500).send(error);
      }
      const totalActiveUsers = result[0].totalActiveUsers;
      res.send({ totalActiveUsers });
    });
  });
   
  db.query(sqlGetDailyNewUsers, (error, results) => {
    if (error) {
      console.error('Error fetching daily new users:', error);
      return res.status(500).send(error);
    }
 
    // Get the total number of days in the current month
    const daysInMonth = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0).getDate();
 
    // Initialize array with zeros for all days of the month
    const dailyNewUsers = new Array(daysInMonth).fill(0);
 
    // Populate the array with results
    results.forEach(result => {
      dailyNewUsers[result.day - 1] = result.newUsers;
    });
 
    res.send(dailyNewUsers);
  });
});
 
app.get('/api/sales_invoices/monthly', (req, res) => {
  const sqlGetMonthlyRevenue = `
    SELECT
      MONTH(dateandtime) AS month,
      SUM(totalprice) AS revenue
    FROM
      sales_invoices
    WHERE
      YEAR(dateandtime) = YEAR(CURDATE())
    GROUP BY
      MONTH(dateandtime)
    ORDER BY
      MONTH(dateandtime)
  `;
 
  db.query(sqlGetMonthlyRevenue, (error, results) => {
    if (error) {
      console.error('Error fetching monthly revenue:', error);
      return res.status(500).send(error);
    }
 
    const monthlyRevenue = new Array(12).fill(0);
    results.forEach(result => {
      monthlyRevenue[result.month - 1] = result.revenue;
    });
 
    res.send(monthlyRevenue);
  });
});
 
// Fetch all sales invoices for a user with total products
app.get("/api/sales-invoices", verifyToken,(req, res) => {
  const username = req.user ? req.user.username : null;

  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  const sql = `
    SELECT 
      saleInvoiceId, 
      customerName, 
      phoneNumber, 
      paymentMethod,
      COUNT(productId) AS totalProducts,
      SUM(quantity) AS totalQuantity,
      totalPrice
    FROM 
      sales_invoices
    WHERE 
      username = ?
    GROUP BY 
      saleInvoiceId, 
      customerName, 
      phoneNumber, 
      paymentMethod
  `;

  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error fetching sales invoices:", err);
      res.status(500).json({ error: "Error fetching sales invoices" });
    } else {
      res.status(200).json(results);
    }
  });
});



// Reports Sales ended  here



// Reports Purchase starts from here

// Fetch purchase orders for view
app.get("/api/purchase-orders/:invoiceId", verifyToken,(req, res) => {
  const { invoiceId } = req.params;
  const username = req.user ? req.user.username : null;

  const sql = `SELECT * FROM purchase_orders WHERE invoiceId = ? AND username = ?`;
  db.query(sql, [invoiceId,username], (err, results) => {
    if (err) {
      console.error("Error fetching purchase orders:", err);
      res.status(500).json({ error: "Error fetching purchase orders" });
    } else {
      res.status(200).json(results);
    }
  });
});


// Fetch purchase orders with necessary details
app.get("/api/purchase-orders", verifyToken,(req, res) => {
  const username = req.user ? req.user.username : null;

  // Ensure username is provided
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  const sql = `
    SELECT 
      invoiceId,
      purchaseInvoiceId,
      SupplierName,
      COUNT(productId) AS totalProducts,
      SUM(quantity) AS totalQuantity,
      SUM(price * quantity - discount) AS totalAmount
    FROM 
      purchase_orders
    WHERE 
      username = ?
    GROUP BY 
      invoiceId, 
      purchaseInvoiceId,
      SupplierName
  `;

  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error fetching purchase orders:", err);
      res.status(500).json({ error: "Error fetching purchase orders" });
    } else {
      res.status(200).json(results);
    }
  });
});


//for header business name fetch according to login credentials


app.get("/get-business-name", async (req, res) => {
  const token = req.cookies.token;
  try {
    const decodedToken = jwt.verify(token, jwtSecretKey,); 
    

    const username = decodedToken.username;

    const query = "SELECT business_name FROM masteradmin_popupForm WHERE username = ? ORDER BY created_at DESC LIMIT 1";

    db.query(query, [username], (err, results) => {
      if (err) {
        console.error("Error fetching business name:", err.message);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: "No business name found for this user" });
      }

      const businessName = results[0].business_name;
      res.status(200).json({ businessName });
    });
  } catch (error) {
    console.error("JWT verification error:", error.message);
    res.status(401).json({ error: "Invalid token" });
  }
});

//header business name is ended
//Reports Purchase was ended 



//dashboard table
// Fetch sales invoices
// Middleware to verify token
const verifyTokens = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Split to get the token part

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, jwtSecretKey);
    req.user = decoded; // Attach user information to the request object if needed
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
};



app.get('/api/sales_invoices', verifyTokens, (req, res) => {
  const query = `
    SELECT saleInvoiceId, customerName, phoneNumber, COUNT(DISTINCT productId) AS totalItems, 
           SUM(totalAmount) AS totalAmount, dateandtime
    FROM sales_invoices
    WHERE username = ?
    GROUP BY saleInvoiceId, customerName, phoneNumber, dateandtime
  `;

  db.query(query, [req.user.username], (err, results) => {
    if (err) {
      console.error('Error fetching invoices:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    res.json(results);
  });
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

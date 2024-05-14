const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "your_secret_key";
const SALT_ROUNDS = 10;

// Create SQLite database connection
const db = new sqlite3.Database("twitterClone.db");

// Middleware
app.use(bodyParser.json());

// API 1: User Registration
app.post("/register", (req, res) => {
  const { username, password, name, gender } = req.body;

  db.get("SELECT * FROM user WHERE username = ?", [username], (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    if (row) {
      return res.status(400).send("User already exists");
    }

    if (password.length < 6) {
      return res.status(400).send("Password is too short");
    }

    bcrypt.hash(password, SALT_ROUNDS, (err, hashedPassword) => {
      if (err) {
        console.error(err.message);
        return res.status(500).send("Internal Server Error");
      }

      const query =
        "INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)";
      db.run(query, [name, username, hashedPassword, gender], (err) => {
        if (err) {
          console.error(err.message);
          return res.status(500).send("Internal Server Error");
        }
        return res.status(200).send("User created successfully");
      });
    });
  });
});

// API 2: User Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM user WHERE username = ?", [username], (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    if (!row) {
      return res.status(400).send("Invalid user");
    }

    bcrypt.compare(password, row.password, (err, result) => {
      if (err) {
        console.error(err.message);
        return res.status(500).send("Internal Server Error");
      }

      if (!result) {
        return res.status(400).send("Invalid password");
      }

      const token = jwt.sign({ username }, SECRET_KEY);
      return res.status(200).json({ jwtToken: token });
    });
  });
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).send("Invalid JWT Token");
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).send("Invalid JWT Token");
    }
    req.user = user;
    next();
  });
};

// API 3: User Tweets Feed
app.get("/user/tweets/feed", authenticateToken, (req, res) => {
  const { username } = req.user;

  const query = `
        SELECT u.username, t.tweet, t.date_time 
        FROM tweet t
        JOIN user u ON t.user_id = u.user_id
        WHERE u.user_id IN (
            SELECT following_user_id 
            FROM follower 
            WHERE follower_user_id = (
                SELECT user_id FROM user WHERE username = ?
            )
        )
        ORDER BY t.date_time DESC
        LIMIT 4
    `;

  db.all(query, [username], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    const tweets = rows.map((row) => ({
      username: row.username,
      tweet: row.tweet,
      dateTime: row.date_time,
    }));

    return res.status(200).json(tweets);
  });
});

// API 4: User Following
app.get("/user/following", authenticateToken, (req, res) => {
  const { username } = req.user;

  const query = `
        SELECT u.name
        FROM user u
        JOIN follower f ON u.user_id = f.following_user_id
        WHERE f.follower_user_id = (
            SELECT user_id FROM user WHERE username = ?
        )
    `;

  db.all(query, [username], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    const following = rows.map((row) => ({
      name: row.name,
    }));

    return res.status(200).json(following);
  });
});

// API 5: User Followers
app.get("/user/followers", authenticateToken, (req, res) => {
  const { username } = req.user;

  const query = `
        SELECT u.name
        FROM user u
        JOIN follower f ON u.user_id = f.follower_user_id
        WHERE f.following_user_id = (
            SELECT user_id FROM user WHERE username = ?
        )
    `;

  db.all(query, [username], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    const followers = rows.map((row) => ({
      name: row.name,
    }));

    return res.status(200).json(followers);
  });
});

// API 6: Tweet Details
app.get("/tweets/:tweetId", authenticateToken, (req, res) => {
  const { username } = req.user;
  const tweetId = req.params.tweetId;

  const query = `
        SELECT t.tweet, COUNT(l.like_id) AS likes, COUNT(r.reply_id) AS replies, t.date_time 
        FROM tweet t
        LEFT JOIN like l ON t.tweet_id = l.tweet_id
        LEFT JOIN reply r ON t.tweet_id = r.tweet_id
        WHERE t.tweet_id = ? AND t.user_id IN (
            SELECT following_user_id 
            FROM follower 
            WHERE follower_user_id = (
                SELECT user_id FROM user WHERE username = ?
            )
        )
    `;

  db.get(query, [tweetId, username], (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    if (!row) {
      return res.status(401).send("Invalid Request");
    }

    const tweetDetails = {
      tweet: row.tweet,
      likes: row.likes,
      replies: row.replies,
      dateTime: row.date_time,
    };

    return res.status(200).json(tweetDetails);
  });
});

// API 7: Tweet Likes
app.get("/tweets/:tweetId/likes", authenticateToken, (req, res) => {
  const { username } = req.user;
  const tweetId = req.params.tweetId;

  const query = `
        SELECT u.username
        FROM user u
        JOIN like l ON u.user_id = l.user_id
        WHERE l.tweet_id = ? AND u.user_id IN (
            SELECT following_user_id 
            FROM follower 
            WHERE follower_user_id = (
                SELECT user_id FROM user WHERE username = ?
            )
        )
    `;

  db.all(query, [tweetId, username], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    const likedBy = rows.map((row) => ({
      username: row.username,
    }));

    return res.status(200).json({ likes: likedBy });
  });
});

// API 8: Tweet Replies
app.get("/tweets/:tweetId/replies", authenticateToken, (req, res) => {
  const { username } = req.user;
  const tweetId = req.params.tweetId;

  const query = `
        SELECT u.name, r.reply
        FROM reply r
        JOIN user u ON r.user_id = u.user_id
        WHERE r.tweet_id = ? AND r.user_id IN (
            SELECT following_user_id 
            FROM follower 
            WHERE follower_user_id = (
                SELECT user_id FROM user WHERE username = ?
            )
        )
    `;

  db.all(query, [tweetId, username], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    const replies = rows.map((row) => ({
      name: row.name,
      reply: row.reply,
    }));

    return res.status(200).json({ replies: replies });
  });
});

// API 9: User Tweets
app.get("/user/tweets", authenticateToken, (req, res) => {
  const { username } = req.user;

  const query = `
        SELECT t.tweet, COUNT(l.like_id) AS likes, COUNT(r.reply_id) AS replies, t.date_time 
        FROM tweet t
        LEFT JOIN like l ON t.tweet_id = l.tweet_id
        LEFT JOIN reply r ON t.tweet_id = r.tweet_id
        WHERE t.user_id = (
            SELECT user_id FROM user WHERE username = ?
        )
        GROUP BY t.tweet_id
    `;

  db.all(query, [username], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    const userTweets = rows.map((row) => ({
      tweet: row.tweet,
      likes: row.likes,
      replies: row.replies,
      dateTime: row.date_time,
    }));

    return res.status(200).json(userTweets);
  });
});

// API 10: Create Tweet
app.post("/user/tweets", authenticateToken, (req, res) => {
  const { username } = req.user;
  const { tweet } = req.body;

  const query =
    'INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, (SELECT user_id FROM user WHERE username = ?), datetime("now"))';

  db.run(query, [tweet, username], (err) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    return res.status(201).send("Created a Tweet");
  });
});

// API 11: Delete Tweet
app.delete("/tweets/:tweetId", authenticateToken, (req, res) => {
  const { username } = req.user;
  const tweetId = req.params.tweetId;

  // Check if the tweet belongs to the user
  const checkOwnershipQuery = "SELECT user_id FROM tweet WHERE tweet_id = ?";
  db.get(checkOwnershipQuery, [tweetId], (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Internal Server Error");
    }

    if (!row || row.user_id !== username) {
      return res.status(401).send("Invalid Request");
    }

    // Delete the tweet
    const deleteQuery = "DELETE FROM tweet WHERE tweet_id = ?";
    db.run(deleteQuery, [tweetId], (err) => {
      if (err) {
        console.error(err.message);
        return res.status(500).send("Internal Server Error");
      }

      return res.status(200).send("Tweet Removed");
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app; // Exporting the Express app instance

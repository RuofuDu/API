const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');

const app = express();


// Skapa en anslutning till databasen
const con = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'webbserverprogrammering'
});

// Testa om anslutningen fungerar
con.connect((err) => {
  if (err) throw err;
  console.log('Ansluten till databasen!');
});

app.use(express.json());

// Hämta data från en tabell med hjälp av API
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;

  // Utför SQL-frågan för att hämta data från en tabell
  con.query('SELECT * FROM users WHERE id = ?', userId, (err, results) => {
    if (err) throw err;
    res.send(results);
  });
});

// Hämta alla data från tabellen "users"
app.get('/users', (req, res) => {
  con.query('SELECT * FROM users', (err, results) => {
    if (err) throw err;
    res.send(results);
  });
});

app.put('/users/:id', (req, res) => {
  const userId = req.params.id;
  const { username, firstname, lastname, password } = req.body;

  // Kryptera lösenordet med hjälp av bcrypt
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) throw err;

    // Utför SQL-frågan för att uppdatera data i tabellen "users"
    con.query('UPDATE users SET username = ?, firstname = ?, lastname = ?, password = ? WHERE id = ?',
      [username, firstname, lastname, hash, userId],
      (err, result) => {
        if (err) throw err;
        res.send(`Användarinformation med ID ${userId} har uppdaterats.`);
      }
    );
  });
});

// Logga in en användare
app.get('/login', (req, res) => {
  const { username, password } = req.query;

  // Kontrollera om användarnamn och lösenord har angetts
  if (!username || !password) {
    return res.status(400).send('Användarnamn och lösenord krävs.');
  }

  // Utför SQL-frågan för att hämta användarinformation från databasen
  con.query('SELECT id, username, firstname, lastname, password FROM users WHERE username = ?',
    username,
    (err, results) => {
      if (err) throw err;

      // Kontrollera om användaren finns i databasen
      if (results.length === 0) {
        return res.status(401).send('Ogiltigt användarnamn eller lösenord.');
      }

      const user = results[0];

      // Kontrollera lösenordet med hjälp av bcrypt
      bcrypt.compare(password, user.password, (err, match) => {
        if (err) throw err;

        // Om lösenordet inte stämmer överens, returnera felmeddelande
        if (!match) {
          return res.status(401).send('Ogiltigt användarnamn eller lösenord.');
        }

        // Om lösenordet stämmer överens, returnera användarinformationen utan lösenordet
        const { password, ...userData } = user;
        res.send(userData);
      });
    }
  );
});

  
const saltRounds = 10; // Antal "rundor" för att kryptera lösenordet
// Skapa en HTTP POST-förfrågan för att lägga till en användare
app.post('/users', async (req, res) => {
  try {
    const { username, password, firstName, lastName } = req.body;

    // Kryptera lösenordet innan det sparas i databasen
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Lägg till användaren i databasen
    const sql = `INSERT INTO users (username, password, firstName, lastName) VALUES (?, ?, ?, ?)`;
    const values = [username, hashedPassword, firstName, lastName];
    const result = await con.query(sql, values);

    res.status(201).send('Användare tillagd!');
  } catch (err) {
    console.error(err);
    res.status(500).send('Ett fel inträffade.');
  }
});


// Starta servern på port 3000
app.listen(3000, () => {
  console.log('Servern är igång på port 3000!');
});


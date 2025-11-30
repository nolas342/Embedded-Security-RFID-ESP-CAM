const mqtt = require('mqtt');
const sqlite3 = require('sqlite3').verbose();
const express = require('express');
const cors = require('cors');
const config = require('./config');

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./db.sqlite', (err) => {
    if (err) console.error("Erreur DB:", err.message);
    else console.log("Base SQLite connectée");
});

// Crée la table si elle n'existe pas
db.run(`CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT,
    door TEXT,
    device TEXT,
    authorized INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Connexion MQTT
const client = mqtt.connect(config.MQTT_BROKER);

client.on('connect', () => {
    console.log("Connecté au broker MQTT");
    client.subscribe(config.MQTT_REQ_TOPIC, (err) => {
        if(err) console.error("Erreur souscription MQTT:", err.message);
        else console.log("Souscrit au topic", config.MQTT_REQ_TOPIC);
    });
});

client.on('message', (topic, message) => {
    let data;
    try {
        data = JSON.parse(message.toString());
    } catch (err) {
        console.error("⚠️ Message MQTT non JSON:", message.toString());
        return;
    }

    const { uid, door, device } = data;
    const authorized = config.AUTHORIZED_UIDS.includes(uid) ? 1 : 0;

    db.run(
        `INSERT INTO access_logs (uid, door, device, authorized) VALUES (?, ?, ?, ?)`,
        [uid, door, device, authorized]
    );

    const respTopic = `${config.MQTT_RESP_BASE}/${device}`;
    const payload = JSON.stringify({ uid, authorized });
    client.publish(respTopic, payload);
});


// Dashboard simple
app.get('/logs', (req, res) => {
    db.all("SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 50", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.listen(3000, () => {
    console.log("Dashboard Express accessible sur http://localhost:3000/logs");
});

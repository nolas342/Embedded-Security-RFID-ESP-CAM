module.exports = {
    MQTT_BROKER: "mqtt://192.168.1.15:1883", // IP de ton PC Mosquitto
    MQTT_REQ_TOPIC: "access/req",
    MQTT_RESP_BASE: "access/resp",
    AUTHORIZED_UIDS: ["73:5B:92:29", "AA:BB:CC:DD"], // UIDs de test autorisés
};

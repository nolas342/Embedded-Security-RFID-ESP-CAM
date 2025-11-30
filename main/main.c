#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "mqtt_client.h"
#include "rc522.h"
#include "driver/rc522_spi.h"
#include "picc/rc522_mifare.h"
#include "sdkconfig.h"

// ==================== CONFIG ====================
#define WIFI_SSID        CONFIG_AC_WIFI_SSID
#define WIFI_PASS        CONFIG_AC_WIFI_PASS
#define DEVICE_ID        CONFIG_AC_DEVICE_ID
#define DOOR_ID          CONFIG_AC_DOOR_ID
#define MQTT_URI         CONFIG_AC_MQTT_URI
#define REQ_TOPIC        CONFIG_AC_MQTT_REQ_TOPIC
#define RESP_BASE        CONFIG_AC_MQTT_RESP_BASE

#define SPI_HOST         CONFIG_AC_RC522_SPI_HOST
#define RC522_SCLK       CONFIG_AC_RC522_SCLK
#define RC522_MOSI       CONFIG_AC_RC522_MOSI
#define RC522_MISO       CONFIG_AC_RC522_MISO
#define RC522_CS         CONFIG_AC_RC522_CS
#define RC522_RST        CONFIG_AC_RC522_RST

static const char *TAG = "RFID_MQTT";
static rc522_driver_handle_t driver;
static rc522_handle_t scanner;
static esp_mqtt_client_handle_t mqtt_client = NULL;
#define UID_MAX_BYTES 10
static EventGroupHandle_t s_wifi_event_group;
static const int WIFI_CONNECTED_BIT = BIT0;

// ==================== Wi-Fi ====================
static void wifi_event_handler(void* arg, esp_event_base_t base, int32_t id, void* data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "Wi-Fi déconnecté, reconnexion…");
        esp_wifi_connect();
        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *e = (const ip_event_got_ip_t*)data;
        ESP_LOGI(TAG, "IP : " IPSTR, IP2STR(&e->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, NULL));

    wifi_config_t wcfg = {0};
    strncpy((char*)wcfg.sta.ssid, WIFI_SSID, sizeof(wcfg.sta.ssid));
    strncpy((char*)wcfg.sta.password, WIFI_PASS, sizeof(wcfg.sta.password));
    wcfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wcfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connexion à %s…", WIFI_SSID);
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
}

// ==================== MQTT ====================
static void handle_backend_response(const char *topic, const char *data) {
    ESP_LOGI(TAG, "Réponse backend reçue: %s", data);
    bool allow = false;
    if (strstr(data, "\"authorized\":1") != NULL) allow = true;

    if (allow) ESP_LOGI(TAG, "👉 Accès AUTORISÉ");
    else ESP_LOGW(TAG, "⛔ Accès REFUSÉ");
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
        {
            ESP_LOGI(TAG, "Connecté à MQTT");
            char resp_topic[64];
            snprintf(resp_topic, sizeof(resp_topic), "%s/%s", RESP_BASE, DEVICE_ID);
            esp_mqtt_client_subscribe(mqtt_client, resp_topic, 1);
            ESP_LOGI(TAG, "Souscrit à %s", resp_topic);
            break;
        }
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "MQTT déconnecté, tentative reconnexion...");
            break;
        case MQTT_EVENT_DATA:
        {
            char topic_str[128], data_str[512];
            snprintf(topic_str, sizeof(topic_str), "%.*s", event->topic_len, event->topic);
            snprintf(data_str, sizeof(data_str), "%.*s", event->data_len, event->data);
            ESP_LOGI(TAG, "MQTT RX: topic=%s payload=%s", topic_str, data_str);
            handle_backend_response(topic_str, data_str);
            break;
        }
        default: break;
    }
}

static void mqtt_start(void) {
   esp_mqtt_client_config_t mqtt_cfg = {
.broker = {
        .address = {
            .uri = "mqtt://192.168.1.15:1883",
            
        }
    }
};
mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
if (mqtt_client == NULL) {
ESP_LOGE(TAG, "Impossible d'initialiser le client MQTT !");
return;
}
esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
esp_mqtt_client_start(mqtt_client);
}

// ==================== RC522 Callback ====================
static void on_picc(void *arg, esp_event_base_t base, int32_t id, void *data) {
    rc522_picc_state_changed_event_t *ev = (rc522_picc_state_changed_event_t *)data;
    rc522_picc_t *picc = ev->picc;
    if (picc->state != RC522_PICC_STATE_ACTIVE) return;

    char uid_str[UID_MAX_BYTES * 3] = {0};
    size_t off = 0;
    for (int i = 0; i < picc->uid.length; i++) {
        off += snprintf(uid_str + off, sizeof(uid_str) - off, "%02X", picc->uid.value[i]);
        if (i < picc->uid.length - 1 && off < sizeof(uid_str) - 1) uid_str[off++] = ':';
    }
    ESP_LOGI(TAG, "Carte détectée → UID=%s", uid_str);

    if (mqtt_client) {
        char payload[256];
        snprintf(payload, sizeof(payload), "{\"uid\":\"%s\",\"door\":\"%s\",\"device\":\"%s\"}", uid_str, DOOR_ID, DEVICE_ID);
        int msg_id = esp_mqtt_client_publish(mqtt_client, REQ_TOPIC, payload, 0, 1, 0);
        ESP_LOGI(TAG, "MQTT TX (%d): %s", msg_id, payload);
    }

    vTaskDelay(pdMS_TO_TICKS(150)); // delay pour éviter overflow RC522
}

// ==================== MAIN ====================
void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_init_sta();
    mqtt_start();

    rc522_spi_config_t cfg = {
        .host_id = (SPI_HOST == 3) ? SPI3_HOST : SPI2_HOST,
        .bus_config = &(spi_bus_config_t){
            .sclk_io_num = RC522_SCLK,
            .mosi_io_num = RC522_MOSI,
            .miso_io_num = RC522_MISO,
        },
        .dev_config = {
            .spics_io_num = RC522_CS,
            .clock_speed_hz = 2 * 1000 * 1000 // SPI réduit pour stabilité
        },
        .rst_io_num = RC522_RST,
    };

    ESP_ERROR_CHECK(rc522_spi_create(&cfg, &driver));
    ESP_ERROR_CHECK(rc522_driver_install(driver));

    rc522_config_t scfg = {.driver = driver};
    ESP_ERROR_CHECK(rc522_create(&scfg, &scanner));
    rc522_register_events(scanner, RC522_EVENT_PICC_STATE_CHANGED, on_picc, NULL);
    ESP_ERROR_CHECK(rc522_start(scanner));

    ESP_LOGI(TAG, "RFID + MQTT prêt. Passe une carte !");
}

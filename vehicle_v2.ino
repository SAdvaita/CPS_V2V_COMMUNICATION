/*
 * ================================================================
 *  V2V Communication System — ESP32  (NO BUZZER VERSION)
 *  Full Protocol Metrics + Multi-Layer Security
 * ================================================================
 *
 *  YOUR PIN LAYOUT (keep your existing wiring — no changes needed):
 *  ──────────────────────────────────────────────────────────────
 *  MPU6050 VCC  → 3.3V          MPU6050 GND → GND
 *  MPU6050 SDA  → GPIO 21       MPU6050 SCL → GPIO 22
 *  MPU6050 AD0  → GND           (fixes address = 0x68)
 *
 *  Brake Button → GPIO 15  (other leg → GND)
 *  Turn  Button → GPIO 5   (other leg → GND)
 *    ⚠ GPIO 5 is an ESP32 strapping pin — OK as long as button
 *      is NOT held down during power-on / reset.
 *
 *  RED  LED  → GPIO 2  → 220Ω → GND   (alert received)
 *  GREEN LED → GPIO 4  → 220Ω → GND   (WiFi/MQTT connected)
 *  YELLOW LED→ GPIO 18 → 220Ω → GND   (message sent)
 *  NO BUZZER
 *
 * ================================================================
 *  BUGS FIXED FROM YOUR PREVIOUS CODE:
 *  1. Rule-2 brake check: old threshold -0.2g fails on a desk.
 *     Added DEMO_MODE flag → relaxes it to -0.05g for static demo.
 *  2. Heartbeat ignored its own vehicle_id — could loop on V2.
 *  3. Missing sequence numbers → Pi couldn't detect dropped packets.
 *  4. Missing gyro read → needed for ML anomaly detection on Pi.
 *  5. No ping/pong → Pi had no way to measure round-trip latency.
 *  6. No metrics publish → dashboard had nothing to display.
 *  7. Missing TOPIC_EMERGENCY subscription.
 *
 * ================================================================
 *  Required libraries (Sketch → Manage Libraries):
 *  • PubSubClient  by Nick O'Leary
 *  • ArduinoJson   by Benoit Blanchon
 *  • Wire          (built-in)
 * ================================================================
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <Wire.h>
#include <ArduinoJson.h>

// ================================================================
//  ► CHANGE ONLY THIS LINE per ESP32
// ================================================================
#define VEHICLE_ID       2     // 1 for Vehicle-1, 2 for Vehicle-2

// ================================================================
//  ► DEMO MODE — set true when ESP32s are stationary on a table
//    Rule-2 (brake decel check) uses a relaxed threshold.
//    Set false in a real vehicle where physical braking occurs.
// ================================================================
#define DEMO_MODE        true

// ================================================================
//  WIFI + BROKER
// ================================================================
const char* WIFI_SSID   = "V2V_SECURE";
const char* WIFI_PASS   = "12345678";
const char* MQTT_SERVER = "192.168.4.1";
const int   MQTT_PORT   = 1883;

// ================================================================
//  PIN DEFINITIONS  (your wiring — do NOT change)
// ================================================================
#define BRAKE_BTN   15
#define TURN_BTN     5    // ⚠ strapping pin — keep unpressed during boot
#define LED_RED      2
#define LED_GREEN    4
#define LED_YELLOW  18
// No buzzer

// ================================================================
//  MPU6050 REGISTERS
// ================================================================
#define MPU_ADDR      0x68
#define PWR_MGMT_1    0x6B
#define ACCEL_XOUT_H  0x3B   // 6 bytes accel, 2 bytes temp, 6 bytes gyro

// ================================================================
//  MQTT TOPICS
// ================================================================
const char* TOPIC_EMERGENCY = "v2v/emergency";
const char* TOPIC_WARNING   = "v2v/warning";
const char* TOPIC_INFO      = "v2v/info";
const char* TOPIC_METRICS   = "v2v/metrics";   // ESP32 → Pi metrics report
const char* TOPIC_PING      = "v2v/ping";       // Pi → ESP32 (latency probe)
const char* TOPIC_PONG      = "v2v/pong";       // ESP32 → Pi (echo back)

// ================================================================
//  TIMING
// ================================================================
const unsigned long SENSOR_MS    =   50;   // 20 Hz sensor read
const unsigned long HEARTBEAT_MS = 5000;   // 5 s heartbeat
const unsigned long METRICS_MS  = 15000;   // 15 s metrics publish
const unsigned long COOLDOWN_MS  =  800;   // button debounce

// ================================================================
//  METRICS  (one block per protocol layer)
// ================================================================
struct {
  // --- PHY / WiFi ---
  int     rssi;
  uint8_t channel;
  long    wifiConnectMs;      // time to associate
  int     wifiReconnects;
  uint32_t txBytes;           // estimated payload bytes sent
  uint32_t rxBytes;           // estimated bytes received

  // --- Transport / MQTT ---
  long    mqttConnectMs;
  int     mqttReconnects;
  uint32_t msgSent;
  uint32_t msgFailed;
  uint32_t msgReceived;
  uint32_t seqNum;            // outgoing sequence counter

  // --- Latency (RTT measured via Pi ping-pong) ---
  long    rttLastMs;
  long    rttMinMs;
  long    rttMaxMs;
  float   rttAvgMs;
  uint32_t rttSamples;

  // --- Throughput window ---
  uint32_t windowCount;
  unsigned long windowStart;
  float    throughputMps;     // messages per second

  // --- Sensor / I2C ---
  uint32_t sensorReads;
  float    sensorRateHz;
  long     sensorReadUs;
  uint32_t i2cErrors;
  float    calNoiseRms;
  float    baseX, baseY, baseZ;

  // --- Security ---
  uint32_t secChecked;
  uint32_t secAccepted;
  uint32_t rule1, rule2, rule3, rule4;
  float    detectMs;          // last detection check latency
} M;

// ================================================================
//  RUNTIME STATE
// ================================================================
WiFiClient   wifiClient;
PubSubClient mqtt(wifiClient);

float accelX=0, accelY=0, accelZ=0;
float gyroX=0,  gyroY=0,  gyroZ=0;
float tempC=0;

bool lastBrake=false, lastTurn=false;

unsigned long lastSentMs=0, lastHbMs=0, lastMetricsMs=0, lastSensorMs=0;
unsigned long rateTimer=0; uint32_t rateCnt=0;
unsigned long pingPendingMs=0; bool pingPending=false;

// Replay ring buffer
struct Msg { unsigned long ts; int vid; char ev[20]; };
Msg ring[10]; int ringIdx=0;

// ================================================================
//  SETUP
// ================================================================
void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println(F("\n╔══════════════════════════════════╗"));
  Serial.printf( "║  V2V Vehicle %d  (Demo=%s)       ║\n",
                 VEHICLE_ID, DEMO_MODE?"ON ":"OFF");
  Serial.println(F("╚══════════════════════════════════╝\n"));

  pinMode(BRAKE_BTN,  INPUT_PULLUP);
  pinMode(TURN_BTN,   INPUT_PULLUP);
  pinMode(LED_RED,    OUTPUT);
  pinMode(LED_GREEN,  OUTPUT);
  pinMode(LED_YELLOW, OUTPUT);
  ledsOff();

  // Boot blink — all three LEDs together x3
  for (int i=0;i<3;i++){
    digitalWrite(LED_RED,HIGH);digitalWrite(LED_GREEN,HIGH);digitalWrite(LED_YELLOW,HIGH);
    delay(300);ledsOff();delay(300);
  }

  // I2C + MPU6050
  Wire.begin(21, 22);
  Wire.setClock(400000);   // 400 kHz fast-mode
  initMPU();
  calibrateMPU();

  // Network
  connectWiFi();
  mqtt.setServer(MQTT_SERVER, MQTT_PORT);
  mqtt.setCallback(onMsgReceived);
  mqtt.setBufferSize(512);
  connectMQTT();

  // Init metrics
  M.rttMinMs      = 999999;
  M.windowStart   = millis();
  rateTimer       = millis();

  digitalWrite(LED_GREEN, HIGH);
  Serial.println(F("[OK] Ready — press BRAKE(GPIO15) or TURN(GPIO5)\n"));
}

// ================================================================
//  LOOP
// ================================================================
void loop() {
  if (!mqtt.connected()){ digitalWrite(LED_GREEN,LOW); connectMQTT(); }
  mqtt.loop();

  unsigned long now = millis();

  // Sensor read @20 Hz
  if (now - lastSensorMs >= SENSOR_MS){
    readMPU();
    lastSensorMs = now;
    rateCnt++;
    if (now - rateTimer >= 1000){
      M.sensorRateHz = rateCnt * 1000.0f / (float)(now - rateTimer);
      rateCnt=0; rateTimer=now;
    }
  }

  checkButtons(now);

  if (now - lastHbMs >= HEARTBEAT_MS){ sendHeartbeat(); lastHbMs=now; }
  if (now - lastMetricsMs >= METRICS_MS){ publishMetrics(); lastMetricsMs=now; }

  // RSSI refresh every 2 s
  static unsigned long rssiT=0;
  if (now-rssiT>2000){ M.rssi=WiFi.RSSI(); M.channel=WiFi.channel(); rssiT=now; }

  digitalWrite(LED_GREEN, mqtt.connected()?HIGH:LOW);
  delay(5);
}

// ================================================================
//  WIFI
// ================================================================
void connectWiFi(){
  Serial.printf("[WiFi] Connecting to %s", WIFI_SSID);
  unsigned long t0=millis();
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  int tries=0;
  while(WiFi.status()!=WL_CONNECTED && tries<40){
    delay(500); Serial.print("."); tries++;
    digitalWrite(LED_YELLOW,!digitalRead(LED_YELLOW));
  }
  digitalWrite(LED_YELLOW,LOW);
  M.wifiConnectMs = (long)(millis()-t0);
  M.wifiReconnects++;

  if(WiFi.status()==WL_CONNECTED){
    M.rssi=WiFi.RSSI(); M.channel=WiFi.channel();
    Serial.printf("\n[WiFi] ✅ OK in %lu ms | IP:%s | RSSI:%d dBm\n",
                  M.wifiConnectMs, WiFi.localIP().toString().c_str(), M.rssi);
  } else {
    Serial.println(F("\n[WiFi] ❌ FAILED"));
    blinkLED(LED_RED,10,200);
  }
}

// ================================================================
//  MQTT
// ================================================================
void connectMQTT(){
  String cid = "V2V_"+String(VEHICLE_ID);
  Serial.printf("[MQTT] Connecting as %s ...", cid.c_str());
  unsigned long t0=millis();
  int tries=0;
  while(!mqtt.connected() && tries<5){
    if(mqtt.connect(cid.c_str())){
      M.mqttConnectMs=(long)(millis()-t0);
      M.mqttReconnects++;
      Serial.printf(" ✅ in %lu ms\n", M.mqttConnectMs);
      mqtt.subscribe(TOPIC_EMERGENCY);
      mqtt.subscribe(TOPIC_WARNING);
      mqtt.subscribe(TOPIC_INFO);
      mqtt.subscribe(TOPIC_PING);    // for latency measurement from Pi
    } else {
      Serial.print("."); delay(1000); tries++;
    }
  }
  if(!mqtt.connected()) Serial.println(F("\n[MQTT] ❌ Failed"));
}

// ================================================================
//  MPU6050 INIT
// ================================================================
void initMPU(){
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(PWR_MGMT_1);
  Wire.write(0x00);   // wake
  byte e=Wire.endTransmission(true);
  delay(100);
  if(e==0) Serial.println(F("[MPU] ✅ Found at 0x68"));
  else     { Serial.printf("[MPU] ❌ Error %d — check wiring!\n",e); blinkLED(LED_RED,5,300); }
}

// ================================================================
//  MPU6050 CALIBRATE
// ================================================================
void calibrateMPU(){
  Serial.print(F("[MPU] Calibrating — keep STILL"));
  const int N=200;
  float sx=0,sy=0,sz=0,ssq=0;
  for(int i=0;i<N;i++){
    float ax,ay,az,gx,gy,gz,t;
    rawRead(ax,ay,az,gx,gy,gz,t);
    sx+=ax; sy+=ay; sz+=az;
    ssq+=ax*ax+ay*ay+az*az;
    delay(5);
    if(i%50==0){ Serial.print("."); digitalWrite(LED_YELLOW,!digitalRead(LED_YELLOW)); }
  }
  digitalWrite(LED_YELLOW,LOW);
  M.baseX=sx/N; M.baseY=sy/N; M.baseZ=sz/N;
  float mean2=(sx/N)*(sx/N)+(sy/N)*(sy/N)+(sz/N)*(sz/N);
  M.calNoiseRms=sqrt(ssq/N - mean2);
  Serial.printf("\n[MPU] ✅ Base X=%.4f Y=%.4f Z=%.4f | Noise=%.5f g\n",
                M.baseX,M.baseY,M.baseZ,M.calNoiseRms);
}

// ================================================================
//  MPU6050 RAW READ (accel + gyro + temp in one 14-byte burst)
// ================================================================
void rawRead(float &ax,float &ay,float &az,
             float &gx,float &gy,float &gz,float &t){
  unsigned long us=micros();
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(ACCEL_XOUT_H);
  uint8_t e=Wire.endTransmission(false);
  if(e){ M.i2cErrors++; return; }
  Wire.requestFrom((uint8_t)MPU_ADDR,(uint8_t)14,(uint8_t)true);

  int16_t rax=Wire.read()<<8|Wire.read();
  int16_t ray=Wire.read()<<8|Wire.read();
  int16_t raz=Wire.read()<<8|Wire.read();
  int16_t rt =Wire.read()<<8|Wire.read();
  int16_t rgx=Wire.read()<<8|Wire.read();
  int16_t rgy=Wire.read()<<8|Wire.read();
  int16_t rgz=Wire.read()<<8|Wire.read();

  ax=rax/16384.0f; ay=ray/16384.0f; az=raz/16384.0f;  // ±2g
  gx=rgx/131.0f;  gy=rgy/131.0f;  gz=rgz/131.0f;      // ±250°/s
  t =rt/340.0f+36.53f;

  M.sensorReadUs=(long)(micros()-us);
  M.sensorReads++;
}

void readMPU(){
  rawRead(accelX,accelY,accelZ,gyroX,gyroY,gyroZ,tempC);
  accelX-=M.baseX; accelY-=M.baseY; accelZ-=M.baseZ;
}

// ================================================================
//  BUTTON CHECK
// ================================================================
void checkButtons(unsigned long now){
  bool brake=!digitalRead(BRAKE_BTN);
  bool turn =!digitalRead(TURN_BTN);

  if(brake && !lastBrake && (now-lastSentMs>COOLDOWN_MS)){
    Serial.println(F("\n🔴 [BRAKE PRESSED]"));
    sendAlert("brake", TOPIC_WARNING);
    lastSentMs=now;
  }
  if(turn && !lastTurn && (now-lastSentMs>COOLDOWN_MS)){
    Serial.println(F("\n🟡 [TURN PRESSED]"));
    sendAlert("turn", TOPIC_INFO);
    lastSentMs=now;
  }
  lastBrake=brake; lastTurn=turn;
}

// ================================================================
//  SEND ALERT
// ================================================================
void sendAlert(const String& ev, const char* topic){
  readMPU();
  M.seqNum++;

  StaticJsonDocument<280> doc;
  doc["vehicle_id"] = VEHICLE_ID;
  doc["event"]      = ev;
  doc["accel_x"]    = accelX;
  doc["accel_y"]    = accelY;
  doc["accel_z"]    = accelZ;
  doc["gyro_x"]     = gyroX;
  doc["gyro_y"]     = gyroY;
  doc["gyro_z"]     = gyroZ;
  doc["temp_c"]     = tempC;
  doc["rssi"]       = M.rssi;
  doc["seq"]        = M.seqNum;
  doc["timestamp"]  = millis();

  String payload; serializeJson(doc, payload);
  uint32_t plen = payload.length();

  bool ok = mqtt.publish(topic, payload.c_str());
  if(ok){
    M.msgSent++; M.windowCount++;
    M.txBytes += plen + 2+1+2+strlen(topic);  // MQTT overhead estimate
    // Throughput window
    float elapsed=(millis()-M.windowStart)/1000.0f;
    if(elapsed>0) M.throughputMps=M.windowCount/elapsed;

    flashLED(LED_YELLOW);
    Serial.printf("[SENT] %s | seq=%u | %u B | ax=%.3f\n",
                  ev.c_str(), M.seqNum, plen, accelX);
  } else {
    M.msgFailed++;
    Serial.println(F("[SENT] ❌ Publish FAILED"));
  }
}

// ================================================================
//  HEARTBEAT
// ================================================================
void sendHeartbeat(){
  StaticJsonDocument<120> doc;
  doc["vehicle_id"] = VEHICLE_ID;
  doc["event"]      = "alive";
  doc["uptime_s"]   = millis()/1000;
  doc["rssi"]       = M.rssi;
  doc["temp_c"]     = tempC;
  doc["seq"]        = M.seqNum;
  doc["timestamp"]  = millis();
  String p; serializeJson(doc,p);
  mqtt.publish(TOPIC_INFO, p.c_str());
  M.msgSent++;

  // Send ping to Pi for RTT measurement
  sendPing();
}

void sendPing(){
  StaticJsonDocument<64> doc;
  doc["vehicle_id"] = VEHICLE_ID;
  doc["ping_ms"]    = millis();
  String p; serializeJson(doc,p);
  mqtt.publish(TOPIC_PONG, p.c_str());   // Pi subscribes to v2v/pong, echoes on v2v/ping
  pingPendingMs=millis(); pingPending=true;
}

// ================================================================
//  RECEIVE CALLBACK
// ================================================================
void onMsgReceived(char* topic, byte* payload, unsigned int length){
  String topicStr=String(topic);
  String msg="";
  for(unsigned int i=0;i<length;i++) msg+=(char)payload[i];
  M.rxBytes+=length;

  // Handle ping echo from Pi → measure RTT
  if(topicStr==TOPIC_PING && pingPending){
    StaticJsonDocument<64> doc;
    if(!deserializeJson(doc,msg)){
      // Check it's our ping echoed back
      int src=doc["src_vid"]|0;
      if(src==VEHICLE_ID){
        long rtt=(long)(millis()-pingPendingMs);
        pingPending=false;
        M.rttLastMs=rtt;
        if(rtt<M.rttMinMs) M.rttMinMs=rtt;
        if(rtt>M.rttMaxMs) M.rttMaxMs=rtt;
        M.rttSamples++;
        M.rttAvgMs+=(rtt-M.rttAvgMs)/M.rttSamples;
        Serial.printf("[RTT] %ld ms | avg=%.1f min=%ld max=%ld\n",
                      rtt,M.rttAvgMs,M.rttMinMs,M.rttMaxMs);
      }
    }
    return;
  }

  // Regular V2V message
  StaticJsonDocument<280> doc;
  if(deserializeJson(doc,msg)) return;

  int    senderID = doc["vehicle_id"]|0;
  String event    = doc["event"]|"unknown";
  float  ax       = doc["accel_x"]|0.0f;
  unsigned long ts= doc["timestamp"]|0UL;

  if(senderID==VEHICLE_ID) return;   // own message
  if(event=="alive") return;         // heartbeat

  M.msgReceived++;
  Serial.printf("\n📩 [RX] V%d → %s | ax=%.3f\n", senderID, event.c_str(), ax);

  // Security check
  unsigned long t0=micros();
  bool valid=validateMessage(senderID, event, ax, ts);
  M.detectMs=(micros()-t0)/1000.0f;

  M.secChecked++;
  if(valid){
    M.secAccepted++;
    Serial.printf("   ✅ VALID (detect=%.3f ms)\n", M.detectMs);
    showAlert(event);
  } else {
    Serial.printf("   🚨 BLOCKED (detect=%.3f ms)\n", M.detectMs);
    showAttackAlert();
  }
}

// ================================================================
//  VALIDATION
// ================================================================
bool validateMessage(int sid, const String& ev, float ax, unsigned long ts){

  // Rule 1 — physically impossible acceleration (±2g range on MPU6050)
  if(fabs(ax)>2.5f){
    Serial.printf("   ❌ Rule-1: |ax|=%.3f > 2.5g impossible\n",ax);
    M.rule1++; return false;
  }

  // Rule 2 — brake without deceleration
  //   DEMO_MODE: -0.05g threshold (desk tilt test)
  //   REAL MODE: -0.15g threshold (actual vehicle braking)
  float brakeThresh = DEMO_MODE ? -0.05f : -0.15f;
  if(ev=="brake" && ax>brakeThresh){
    Serial.printf("   ❌ Rule-2: brake claimed ax=%.3f (threshold %.2f)\n",
                  ax, brakeThresh);
    M.rule2++; return false;
  }

  // Rule 3 — stale / replayed old timestamp (>10 s)
  unsigned long age=millis()-ts;
  if(age>10000UL){
    Serial.printf("   ❌ Rule-3: age=%lu ms > 10 s\n",age);
    M.rule3++; return false;
  }

  // Rule 4 — exact replay (same sender + event + timestamp within 2 s)
  for(int i=0;i<10;i++){
    if(ring[i].vid==sid && String(ring[i].ev)==ev
       && labs((long)(ring[i].ts-ts))<2000){
      M.rule4++; return false;
    }
  }
  ring[ringIdx]={ts,sid,{}}; ev.toCharArray(ring[ringIdx].ev,20);
  ringIdx=(ringIdx+1)%10;

  return true;
}

// ================================================================
//  ALERT DISPLAY  (LEDs only — no buzzer)
// ================================================================
void showAlert(const String& ev){
  if(ev=="brake"){
    Serial.println(F("   🔴 BRAKE ALERT"));
    for(int i=0;i<3;i++){
      digitalWrite(LED_RED,HIGH);delay(300);
      digitalWrite(LED_RED,LOW); delay(150);
    }
    digitalWrite(LED_RED,HIGH);delay(2000);digitalWrite(LED_RED,LOW);
  } else if(ev=="turn"){
    Serial.println(F("   🟡 TURN SIGNAL"));
    for(int i=0;i<2;i++){
      digitalWrite(LED_YELLOW,HIGH);delay(400);
      digitalWrite(LED_YELLOW,LOW); delay(200);
    }
  }
}

void showAttackAlert(){
  Serial.println(F("   🚨 ATTACK — rapid red blink"));
  for(int i=0;i<8;i++){
    digitalWrite(LED_RED,HIGH);delay(80);
    digitalWrite(LED_RED,LOW); delay(80);
  }
}

// ================================================================
//  PUBLISH METRICS  (Pi reads and displays on dashboard)
// ================================================================
void publishMetrics(){
  // Compute overhead ratio
  uint32_t mqttOh = M.msgSent*(2+1+2+11);   // fixed+var hdr + "v2v/warning"
  uint32_t coapOh = M.msgSent*8;             // CoAP NON fixed ~8B
  float deliv = M.msgSent>0
    ? 100.0f*(M.msgSent-M.msgFailed)/M.msgSent : 0.0f;

  StaticJsonDocument<512> doc;
  doc["type"]          = "metrics";
  doc["vehicle_id"]    = VEHICLE_ID;
  doc["timestamp"]     = millis();
  // WiFi
  doc["wifi_rssi"]     = M.rssi;
  doc["wifi_ch"]       = M.channel;
  doc["wifi_con_ms"]   = M.wifiConnectMs;
  doc["wifi_reconnects"]= M.wifiReconnects;
  // MQTT
  doc["mqtt_con_ms"]   = M.mqttConnectMs;
  doc["mqtt_reconnects"]= M.mqttReconnects;
  doc["msg_sent"]      = M.msgSent;
  doc["msg_failed"]    = M.msgFailed;
  doc["msg_received"]  = M.msgReceived;
  doc["delivery_pct"]  = deliv;
  doc["throughput_mps"]= M.throughputMps;
  // Latency
  doc["rtt_last_ms"]   = M.rttLastMs;
  doc["rtt_avg_ms"]    = M.rttAvgMs;
  doc["rtt_min_ms"]    = M.rttMinMs==999999?0:M.rttMinMs;
  doc["rtt_max_ms"]    = M.rttMaxMs;
  // Overhead
  doc["mqtt_oh_bytes"] = mqttOh;
  doc["coap_oh_bytes"] = coapOh;
  doc["tx_bytes"]      = M.txBytes;
  // Sensor
  doc["sensor_hz"]     = M.sensorRateHz;
  doc["sensor_us"]     = M.sensorReadUs;
  doc["i2c_errors"]    = M.i2cErrors;
  doc["cal_noise"]     = M.calNoiseRms;
  // Security
  doc["sec_checked"]   = M.secChecked;
  doc["sec_accepted"]  = M.secAccepted;
  doc["sec_rule1"]     = M.rule1;
  doc["sec_rule2"]     = M.rule2;
  doc["sec_rule3"]     = M.rule3;
  doc["sec_rule4"]     = M.rule4;
  doc["detect_ms"]     = M.detectMs;

  String p; serializeJson(doc,p);
  mqtt.publish(TOPIC_METRICS, p.c_str());
  Serial.println(F("[METRICS] Published to v2v/metrics"));
  printMetricsSerial();
}

void printMetricsSerial(){
  Serial.println(F("\n┌─────────── METRICS SNAPSHOT ───────────┐"));
  Serial.printf( "│ WiFi RSSI   : %d dBm  CH:%d\n", M.rssi, M.channel);
  Serial.printf( "│ Delivery    : %.1f%%  Throughput:%.2f msg/s\n",
    M.msgSent>0?100.0f*(M.msgSent-M.msgFailed)/M.msgSent:0,M.throughputMps);
  Serial.printf( "│ RTT last    : %ld ms  avg:%.1f  min:%ld  max:%ld\n",
    M.rttLastMs,M.rttAvgMs,M.rttMinMs==999999?0:M.rttMinMs,M.rttMaxMs);
  Serial.printf( "│ Sensor rate : %.1f Hz  read:%ld µs  I2C err:%u\n",
    M.sensorRateHz,M.sensorReadUs,M.i2cErrors);
  Serial.printf( "│ Security    : checked=%u accepted=%u\n",M.secChecked,M.secAccepted);
  Serial.printf( "│              R1=%u R2=%u R3=%u R4=%u\n",
    M.rule1,M.rule2,M.rule3,M.rule4);
  Serial.println(F("└────────────────────────────────────────┘\n"));
}

// ================================================================
//  HELPERS
// ================================================================
void ledsOff(){
  digitalWrite(LED_RED,LOW);digitalWrite(LED_GREEN,LOW);digitalWrite(LED_YELLOW,LOW);
}
void blinkLED(int pin,int n,int ms){
  for(int i=0;i<n;i++){digitalWrite(pin,HIGH);delay(ms);digitalWrite(pin,LOW);delay(ms);}
}
void flashLED(int pin){
  digitalWrite(pin,HIGH);delay(150);digitalWrite(pin,LOW);
}

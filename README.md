# Vehicle-to-Vehicle (V2V) Communication with Rule-Based Intrusion Detection System

## Overview

This project presents a low-cost and secure Vehicle-to-Vehicle (V2V) communication system using ESP32 microcontrollers, MPU6050 sensors, and a Raspberry Pi 4. The system enables vehicles to exchange safety-critical information such as emergency braking and hazard alerts over a local Wi-Fi network using the MQTT protocol. To improve communication security, a rule-based Intrusion Detection System (IDS) validates incoming messages and prevents attacks such as false brake alerts, replay attacks, stale packets, and sensor spoofing. A real-time Flask dashboard provides live monitoring of communication metrics, while all events are automatically logged into CSV files for future analysis.

---

## Problem Statement

Vehicle-to-Vehicle communication enables vehicles to exchange safety-critical information before a human driver can react. However, wireless communication channels are vulnerable to attacks including false brake alerts, replay attacks, stale messages, and sensor spoofing. Existing V2V technologies such as DSRC and C-V2X require expensive specialized hardware and certificate infrastructure, making them unsuitable for educational and research environments.

This project addresses these challenges by implementing a secure, real-time V2V communication system using low-cost IoT hardware while providing protocol performance monitoring and attack detection.

---

## Features

- Low-cost V2V communication using ESP32 and Raspberry Pi
- MQTT publish/subscribe messaging
- Rule-based Intrusion Detection System (IDS)
- Replay attack prevention
- Sensor validation using MPU6050
- Real-time Flask dashboard
- Live communication metrics
- RSSI and latency monitoring
- CSV event logging
- Protocol performance visualization

---

## Hardware Requirements

- 2 × ESP32 DevKit
- 2 × MPU6050 Accelerometer/Gyroscope
- 1 × Raspberry Pi 4
- Breadboards
- Push Buttons
- USB Power Supply / Power Banks
- Jumper Wires

---

## Software Requirements

### Embedded

- Arduino IDE
- ESP32 Board Package
- PubSubClient Library
- Wire Library

### Raspberry Pi

- Raspberry Pi OS
- Python 3
- Flask
- Paho MQTT
- Mosquitto MQTT Broker

### Dashboard

- HTML
- CSS
- JavaScript

---

## Technologies Used

- ESP32
- Raspberry Pi 4
- MPU6050
- MQTT
- Mosquitto
- Python
- Flask
- HTML
- CSS
- JavaScript
- CSV Logging

---

## Project Structure

```
V2V-Communication/
│
├── esp32/
│   ├── vehicle_v1/
│   ├── vehicle_v2/
│   └── config.h
│
├── raspberry_pi/
│   ├── app.py
│   ├── mqtt_listener.py
│   ├── logger.py
│   ├── templates/
│   └── static/
│
├── logs/
│   └── v2v_log.csv
│
├── screenshots/
│
└── README.md
```

---

## Working

1. Both ESP32 nodes connect to the Wi-Fi network.
2. The Raspberry Pi runs the Mosquitto MQTT broker.
3. Vehicle nodes publish and subscribe to MQTT topics.
4. Sensor data from MPU6050 is attached to every safety message.
5. Incoming messages are validated using IDS rules.
6. Valid messages are forwarded to other vehicles.
7. Invalid or malicious messages are blocked.
8. Dashboard displays live communication statistics.
9. All communication events are stored in CSV files.

---

## Intrusion Detection Rules

### Rule 1 – Invalid Sensor Values

Blocks messages containing impossible acceleration values greater than 16g.

### Rule 2 – False Brake Detection

Brake alerts are accepted only when the MPU6050 confirms vehicle deceleration.

### Rule 3 – Stale Packet Detection

Messages older than 10 seconds are rejected.

### Rule 4 – Replay Attack Prevention

Duplicate packets received within a 2-second window are blocked.

---

## Performance Metrics

The system continuously monitors:

- Wi-Fi Connection Time
- MQTT Connection Time
- RSSI
- Round Trip Time (RTT)
- MQTT Throughput
- Packet Delivery Percentage
- Message Latency
- Sensor Read Time
- Attack Count
- Message Validation Time

---

## Dashboard Features

The real-time Flask dashboard displays:

- Vehicle Status
- Sensor Readings
- RSSI
- Communication Latency
- MQTT Metrics
- Packet Delivery Rate
- IDS Alerts
- Replay Attack Count
- Throughput
- Live Communication Status

---

## CSV Logging

Every MQTT message is automatically stored in a CSV file.

Logged information includes:

- Timestamp
- Vehicle ID
- Topic
- Event Type
- Sensor Readings
- RSSI
- Sequence Number
- Validation Result
- Block Reason
- Payload Size
- Detection Time

---

## Experimental Validation

The following experiments were successfully completed:

- Two-node V2V communication
- MQTT publish/subscribe communication
- Invalid sensor value detection
- False brake event detection
- Replay attack detection
- Stale packet rejection
- Real-time dashboard monitoring
- CSV event logging
- Communication performance measurement

---

## Results

- Both ESP32 nodes successfully connected to the Wi-Fi network and MQTT broker.
- Reliable MQTT-based message exchange was achieved.
- The IDS successfully detected and blocked malicious messages.
- Replay attacks were successfully prevented.
- Sensor validation accurately filtered false brake alerts.
- Low communication latency was maintained throughout testing.
- The dashboard displayed real-time communication and security metrics.
- CSV logging successfully recorded all communication events and attacks.
- The system achieved secure and reliable Vehicle-to-Vehicle communication using low-cost IoT hardware.

---

## Why MQTT?

MQTT was selected because it provides:

- Lightweight communication
- Low bandwidth usage
- Publish/Subscribe architecture
- Persistent TCP connections
- Dynamic IP support
- One-to-many communication
- Reliable message delivery using QoS
- Excellent compatibility with ESP32

Compared to HTTP and CoAP, MQTT offers lower communication overhead and is better suited for real-time IoT-based V2V communication.

---

## Future Enhancements

- Multi-vehicle communication
- GPS integration
- TLS-encrypted MQTT communication
- Machine Learning-based Intrusion Detection System
- Cloud-based monitoring dashboard
- Vehicle authentication using digital certificates
- Edge AI for anomaly detection

---

## Conclusion

This project demonstrates that secure and reliable Vehicle-to-Vehicle communication can be achieved using affordable IoT hardware. By combining ESP32 microcontrollers, MPU6050 sensors, Raspberry Pi, MQTT messaging, and a rule-based Intrusion Detection System, the system effectively detects malicious communication while maintaining low latency and reliable message delivery. The real-time dashboard and automated CSV logging provide complete visibility into system performance, making the platform suitable for IoT research, education, and rapid prototyping.

---



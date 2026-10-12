from gpiozero import LED, DigitalInputDevice
from time import sleep

# -------------------------------
# PIN ASSIGNMENTS (BCM numbering)
# -------------------------------
LED_PIN = 17
SENSOR_PIN = 27

# -------------------------------
# SETUP
# -------------------------------
led = LED(LED_PIN)

# Water sensor connected to GPIO 27
# pull_up=True means the input normally stays HIGH
sensor = DigitalInputDevice(SENSOR_PIN, pull_up=True)

print("===================================")
print(" Water Level Sensor IoT Project")
print("===================================")
print("GPIO 27 = Water Sensor")
print("GPIO 17 = LED / Actuator")
print("System started...")
print("Press Ctrl+C to stop.")

try:
    while True:

        # LOW = water detected
        if sensor.value == 0:

            print("Water detected -> Actuator BLINKING")

            # Blink actuator
            led.on()
            sleep(0.5)

            led.off()
            sleep(0.5)

        else:

            print("No water detected -> Actuator OFF")
            led.off()

            sleep(0.5)

except KeyboardInterrupt:
    print("\nProgram stopped.")

finally:
    led.off()
    sensor.close()
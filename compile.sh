#!/bin/bash
ant && jarsigner -storepass 123456 -keystore pKeyStore dist/lib/agora-applet.jar devsignature && cp dist/lib/agora-applet.jar ../referendum15oct/public/lib/ && killall java


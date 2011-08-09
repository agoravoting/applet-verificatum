#!/usr/bin/env bash

E=/home/edulix/proyectos/wadobo/agora/frontend/agoraonrails/applet-verificatum

java -classpath $E/deps/apache-commons-codec-1.4.jar:$E/deps/bcprov-1.45.jar:$E/deps/verificatum.jar:$E/dist/lib/agora-applet.jar org.agora.BallotVerifier $@

#!/usr/bin/env bash

java -classpath deps/apache-commons-codec-1.4.jar:deps/bcprov-1.45.jar:deps/verificatum.jar:dist/lib/agora-applet.jar org.agora.BallotVerifier $@

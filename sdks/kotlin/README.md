# Rembrane Kotlin SDK

Dependency-free Kotlin/JVM client for the authenticated Rembrane REST API.
It uses the JDK HTTP client, refuses redirects, requires HTTPS except for
explicit loopback development endpoints, bounds response bodies, and supports
an injected transport for deterministic tests.

Compile the main client and smoke test with Kotlin 1.9 or newer:

```sh
kotlinc src/main/kotlin/rembrane/RembraneClient.kt \
  src/test/kotlin/rembrane/Smoke.kt \
  -include-runtime -d rembrane-smoke.jar
java -jar rembrane-smoke.jar
```

`ChannelProcessorMessage` and `ChannelProcessorAcknowledgement` provide strict
typed validation and canonical JSON serialization for cooperative JVM/Android
bot processors. Parse inbound JSON with the host application's JSON library
against the published Rembrane schema, then construct
`ChannelProcessorMessage` before processing it.

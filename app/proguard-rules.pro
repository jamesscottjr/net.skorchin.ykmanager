# YubiKit is pure Java/Kotlin, no proguard issues expected.
# Keep YubiKit classes if you enable R8 later.
-keep class com.yubico.yubikit.** { *; }
-dontwarn org.jspecify.annotations.**
-dontwarn org.slf4j.**

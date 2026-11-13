import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "net.skorchin.ykmanager"
    compileSdk = 37

    defaultConfig {
        applicationId = "net.skorchin.ykmanager"
        minSdk = 24
        targetSdk = 36
        versionCode = 31
        versionName = "2.29"
    }

    // Release signing material is resolved, in order, from:
    //   1. keystore.properties at the project root (local developer builds), or
    //   2. the YK_KEYSTORE_FILE / YK_KEYSTORE_PASSWORD / YK_KEY_ALIAS / YK_KEY_PASSWORD
    //      environment variables (GitHub Actions, see .github/workflows/release.yml).
    // If neither is present the release build is signed with the debug key so CI
    // builds on forks and pull requests still produce an installable package.
    val releaseSigning: Map<String, String>? = run {
        val propsFile = rootProject.file("keystore.properties")
        if (propsFile.exists()) {
            val props = Properties()
            propsFile.inputStream().use { props.load(it) }
            mapOf(
                "storeFile" to rootProject.file(props.getProperty("storeFile")).absolutePath,
                "storePassword" to props.getProperty("storePassword"),
                "keyAlias" to props.getProperty("keyAlias"),
                "keyPassword" to props.getProperty("keyPassword"),
            )
        } else {
            val file = System.getenv("YK_KEYSTORE_FILE")
            if (!file.isNullOrBlank() && File(file).exists()) {
                mapOf(
                    "storeFile" to file,
                    "storePassword" to (System.getenv("YK_KEYSTORE_PASSWORD") ?: ""),
                    "keyAlias" to (System.getenv("YK_KEY_ALIAS") ?: ""),
                    "keyPassword" to (System.getenv("YK_KEY_PASSWORD") ?: ""),
                )
            } else null
        }
    }

    signingConfigs {
        if (releaseSigning != null) {
            create("release") {
                storeFile = File(releaseSigning.getValue("storeFile"))
                storePassword = releaseSigning.getValue("storePassword")
                keyAlias = releaseSigning.getValue("keyAlias")
                keyPassword = releaseSigning.getValue("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (releaseSigning != null) {
                signingConfigs.getByName("release")
            } else {
                logger.warn("YK Manager: no release keystore found; signing release build with the debug key.")
                signingConfigs.getByName("debug")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }


    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
            )
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

// Lock the release runtime classpath so software-composition analysis (OSV-Scanner,
// Dependabot) sees exactly what ships. Refresh with:
//   ./gradlew :app:dependencies --configuration releaseRuntimeClasspath --write-locks
configurations.matching { it.name == "releaseRuntimeClasspath" }.configureEach {
    resolutionStrategy.activateDependencyLocking()
}

dependencies {
    // Yubico Android SDK (YubiKit)
    val yubikit = "3.3.0"
    implementation("com.yubico.yubikit:android:$yubikit")
    implementation("com.yubico.yubikit:management:$yubikit")
    implementation("com.yubico.yubikit:yubiotp:$yubikit")
    implementation("com.yubico.yubikit:oath:$yubikit")
    implementation("com.yubico.yubikit:piv:$yubikit")
    implementation("com.yubico.yubikit:openpgp:$yubikit")
    implementation("com.yubico.yubikit:fido:$yubikit")
    implementation("com.yubico.yubikit:support:$yubikit")

    // Android Credential Manager provider API (passkey provider, Android 14+)
    implementation("androidx.credentials:credentials:1.6.0")

    // X.509 certificate / CSR generation and PKCS#12 / PEM import for PIV
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    // QR code scanning for adding OATH accounts
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")

    // Jetpack Compose
    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // AndroidX
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

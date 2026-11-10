import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "net.skorchin.ykmanager"
    compileSdk = 36

    defaultConfig {
        applicationId = "net.skorchin.ykmanager"
        minSdk = 24
        targetSdk = 36
        versionCode = 23
        versionName = "2.21"
    }

    signingConfigs {
        // Uses keystore.properties at the project root if present, so the
        // release APK is properly signed. Falls back to the debug key.
        create("release") {
            val propsFile = rootProject.file("keystore.properties")
            if (propsFile.exists()) {
                val props = Properties()
                propsFile.inputStream().use { props.load(it) }
                storeFile = rootProject.file(props.getProperty("storeFile"))
                storePassword = props.getProperty("storePassword")
                keyAlias = props.getProperty("keyAlias")
                keyPassword = props.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
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

dependencies {
    // Yubico Android SDK (YubiKit)
    val yubikit = "3.1.0"
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
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // QR code scanning for adding OATH accounts
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // Jetpack Compose
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
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
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

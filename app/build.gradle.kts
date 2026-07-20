import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing: local self-signed key, config kept OUT of git in
// local.properties (keystore.path/.password). Debug-fallback if absent.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
val ksPath: String? = localProps.getProperty("keystore.path")

android {
    namespace = "org.qpgp"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.qpgp"
        minSdk = 28
        targetSdk = 35
        versionCode = 4
        versionName = "0.3.0"
    }

    if (ksPath != null) {
        signingConfigs {
            create("release") {
                storeFile = file(ksPath)
                storePassword = localProps.getProperty("keystore.password")
                keyAlias = localProps.getProperty("keystore.alias", "qpgp")
                keyPassword = localProps.getProperty("keystore.password")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (ksPath != null) signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // Deterministic-ish builds: strip out variable metadata
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
    packaging {
        resources.excludes += setOf("META-INF/*.version", "META-INF/LICENSE*", "META-INF/NOTICE*", "kotlin/**")
    }
}

dependencies {
    // Minimal dependency budget — every entry here is attack surface.
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")

    // The single cryptographic dependency: BouncyCastle (audited, FIPS-track lineage).
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")

    // QR (identity exchange): ZXing core (pure Java, generation+decoding) and
    // the embedded camera scanner. Camera permission is requested ONLY while
    // the scan screen is open. QR content is never interpreted — it feeds the
    // same strict Armor parser as pasted text.
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // Biometric unlock (opt-in): passphrase sealed under a hardware Keystore
    // key that requires biometric auth per use.
    implementation("androidx.biometric:biometric:1.1.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.80")
}

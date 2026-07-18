plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.qpgp"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.qpgp"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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
    // Provides ML-KEM (FIPS 203), ML-DSA (FIPS 204), X25519, Ed25519,
    // ChaCha20-Poly1305, HKDF, Argon2id — all in one pinned artifact.
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.80")
}

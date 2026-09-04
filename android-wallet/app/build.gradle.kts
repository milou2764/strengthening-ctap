plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.ctapwallet"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.ctapwallet"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        resources {
            excludes += "/META-INF/versions/9/OSGI-INF/MANIFEST.MF"
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("com.google.android.material:material:1.12.0")

    // CTAP hybrid (caBLE v2) authenticator flow.
    implementation("io.github.zxing-cpp:android:2.3.0")     // QR decode
    implementation("com.squareup.okhttp3:okhttp:4.12.0")    // tunnel WebSocket
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")  // HKDF + point decompression
    implementation("co.nstant.in:cbor:0.9")                 // CBOR (CTAP + COSE)
    implementation("androidx.camera:camera-core:1.4.2")
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
}

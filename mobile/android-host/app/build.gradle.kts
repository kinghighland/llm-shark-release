plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.llmshark.mobile"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.llmshark.mobile"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.1.1"
        ndk {
            abiFilters += listOf("x86_64", "arm64-v8a")
        }
    }

    signingConfigs {
        create("release") {
            // 从环境变量读取签名配置
            storeFile = file("C:/Users/kingh/.android/sudokung-release.keystore")
            storePassword = System.getenv("RELEASE_KEYSTORE_PASSWORD") ?: ""
            keyAlias = System.getenv("RELEASE_KEY_ALIAS") ?: ""
            keyPassword = System.getenv("RELEASE_KEY_PASSWORD") ?: ""
        }
    }

    buildTypes {
        getByName("debug") {
            isDebuggable = true
            isMinifyEnabled = false
        }
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

tasks.register("verifyJniLibs") {
    doLast {
        val required = listOf(
            "src/main/jniLibs/x86_64/libffi_bridge.so",
            "src/main/jniLibs/arm64-v8a/libffi_bridge.so",
        )
        val missing = required.filter { !file(it).exists() }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "Missing Rust JNI libs:\n" + missing.joinToString("\n") +
                    "\nBuild ffi_bridge with feature 'jni' and copy outputs to app/src/main/jniLibs/<abi>/"
            )
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn("verifyJniLibs")
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
}

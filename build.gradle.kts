plugins {
    kotlin("jvm") version "2.0.0"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("com.github.ben-manes.versions") version "0.51.0" //Gradle -> Help -> dependencyUpdates
}

group = "com.nickcoblentz.montoya"
version = "0.1.1"

repositories {
    mavenLocal()
    mavenCentral()
    maven(url="https://jitpack.io") {
        content {
            includeGroup("com.github.milchreis")
            includeGroup("com.github.ncoblentz")
        }
    }
}

dependencies {
    testImplementation(kotlin("test"))
    //implementation("com.nickcoblentz.montoya:MontoyaLibrary:0.1.10")
    implementation("com.github.ncoblentz:BurpMontoyaLibrary:0.1.13")
    implementation("net.portswigger.burp.extensions:montoya-api:2023.12.1")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(21)
}
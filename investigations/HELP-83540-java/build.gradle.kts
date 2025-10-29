plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // 1.8.0 fails with "Error in KMS response"
    // implementation("org.mongodb:mongodb-crypt:1.8.0")
    // 1.11.0 passes:
    implementation("org.mongodb:mongodb-crypt:1.11.0")
}

tasks.test {
    useJUnitPlatform()
}